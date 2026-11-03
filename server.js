import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import { neon } from "@neondatabase/serverless";
import { createRemoteJWKSet, jwtVerify } from "jose";
import Stripe from "stripe";
import { createHmac, randomUUID } from "node:crypto";
import nodemailer from "nodemailer";

const app = express();
app.disable("x-powered-by");
app.use(helmet());

const required = ["DATABASE_URL", "NEON_AUTH_URL", "NEON_AUTH_JWKS_URL", "ADMIN_EMAILS", "SITE_ORIGIN"];

for (const name of required) {
  if (!process.env[name]) {
    console.error("Missing environment variable: " + name);
    process.exit(1);
  }
}
const sql = neon(process.env.DATABASE_URL);

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

const FORMULA_PRICES = Object.freeze({
  famille: 199,
  moyen: 199,
  difficile: 299,
  extreme: 399,
  nuit: 399,
  pack_complet: 999
});
const PACK_FORMULAS = ["famille", "moyen", "difficile", "extreme", "nuit"];
const FREE_FORMULAS = new Set(["enfant", "facile"]);

function getFormulaLabel(formula) {
  return ({
    enfant: "Enfant",
    facile: "Facile",
    famille: "Famille",
    moyen: "Moyen",
    difficile: "Difficile",
    extreme: "Extrême",
    nuit: "Nuit",
    pack_complet: "Pack complet"
  })[formula] || formula;
}

// Stripe must receive the unparsed body to verify its signature.
// This route is deliberately registered before express.json().
app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(503).send("Stripe webhook is not configured.");
  }

  let event;
  try {
    const signature = req.headers["stripe-signature"];
    event = stripe.webhooks.constructEvent(req.body, signature, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (error) {
    console.error("Stripe webhook signature failed:", error.message);
    return res.status(400).send("Invalid Stripe signature.");
  }

  if (event.type !== "checkout.session.completed") {
    return res.json({ received: true, ignored: true });
  }

  const session = event.data.object;
  if (session.payment_status !== "paid" || session.mode !== "payment") {
    return res.json({ received: true, ignored: true });
  }

  try {
    const insertedEvent = await sql`
      INSERT INTO public.stripe_webhook_events (event_id, event_type)
      VALUES (${event.id}, ${event.type})
      ON CONFLICT (event_id) DO NOTHING
      RETURNING event_id
    `;
    if (!insertedEvent.length) return res.json({ received: true, duplicate: true });

    const userId = String(session.metadata?.user_id || "");
    const village = String(session.metadata?.village || "");
    const formula = String(session.metadata?.formula || "");
    const expectedAmount = FORMULA_PRICES[formula];

    if (!userId || village !== "humbert" || !expectedAmount ||
        Number(session.amount_total) !== expectedAmount ||
        String(session.currency).toLowerCase() !== "eur") {
      console.error("Stripe session rejected: invalid metadata or amount.", session.id);
      return res.status(400).send("Invalid payment metadata.");
    }

    const orderRows = await sql`
      INSERT INTO public.payment_orders
        (user_id, village, stripe_session_id, stripe_payment_intent_id,
         amount_cents, currency, status, paid_at)
      VALUES
        (${userId}, ${village}, ${session.id},
         ${typeof session.payment_intent === "string" ? session.payment_intent : null},
         ${expectedAmount}, 'eur', 'paid', NOW())
      ON CONFLICT (stripe_session_id) DO UPDATE
        SET status = 'paid', paid_at = COALESCE(public.payment_orders.paid_at, NOW())
      RETURNING id
    `;
    const orderId = orderRows[0]?.id;

    const grantedFormulas = formula === "pack_complet" ? PACK_FORMULAS : [formula];
    for (const item of grantedFormulas) {
      await sql`
        INSERT INTO public.user_formula_access
          (user_id, village, formula, source, payment_order_id)
        VALUES (${userId}, ${village}, ${item}, 'stripe', ${orderId})
        ON CONFLICT (user_id, village, formula) DO NOTHING
      `;
    }

    return res.json({ received: true });
  } catch (error) {
    console.error("Stripe webhook processing failed:", error.message);
    return res.status(500).send("Webhook processing failed.");
  }
});

app.use(express.json({ limit: "7mb" }));

// Free formulas are granted to the authenticated player without Stripe.
app.post("/api/formulas/grant-free", requireUser, async (req, res) => {
  const village = String(req.body?.village || "");
  const formula = String(req.body?.formula || "");
  if (village !== "humbert" || !FREE_FORMULAS.has(formula)) {
    return res.status(400).json({ error: "Formule gratuite ou village invalide." });
  }
  try {
    await sql`
      INSERT INTO public.user_formula_access (user_id, village, formula, source)
      VALUES (${req.user.id}, ${village}, ${formula}, 'free')
      ON CONFLICT (user_id, village, formula) DO NOTHING
    `;
    res.json({ granted: true, formula, village });
  } catch (error) {
    console.error("Grant free formula failed:", error.message);
    res.status(500).json({ error: "Impossible d'activer cette formule gratuite." });
  }
});

app.get("/api/formulas/access", requireUser, async (req, res) => {
  const village = String(req.query?.village || "humbert");
  if (village !== "humbert") return res.status(400).json({ error: "Village invalide." });
  try {
    const rows = await sql`
      SELECT formula, source, granted_at
      FROM public.user_formula_access
      WHERE user_id = ${req.user.id} AND village = ${village}
      ORDER BY granted_at ASC
    `;
    res.json({ village, formulas: rows });
  } catch (error) {
    console.error("Read formula access failed:", error.message);
    res.status(500).json({ error: "Impossible de vérifier tes formules." });
  }
});

app.post("/api/payments/create-checkout-session", requireUser, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: "Le paiement Stripe n'est pas encore configuré." });

  const village = String(req.body?.village || "");
  const formula = String(req.body?.formula || "");
  const amount = FORMULA_PRICES[formula];

  if (village !== "humbert" || !amount) {
    return res.status(400).json({ error: "Formule ou village invalide." });
  }

  try {
    const owned = await sql`
      SELECT formula
      FROM public.user_formula_access
      WHERE user_id = ${req.user.id} AND village = ${village}
    `;
    const ownedSet = new Set(owned.map((row) => row.formula));

    if (formula === "pack_complet" && PACK_FORMULAS.some((item) => ownedSet.has(item))) {
      return res.status(409).json({
        error: "Tu possèdes déjà une partie des formules. Achète uniquement les formules qui te manquent."
      });
    }
    if (formula !== "pack_complet" && ownedSet.has(formula)) {
      return res.status(409).json({ error: "Tu possèdes déjà cette formule. Tu ne seras pas facturé une deuxième fois." });
    }

    const origin = process.env.SITE_ORIGIN.split(",").map((value) => value.trim()).filter(Boolean)[0];
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [{
        quantity: 1,
        price_data: {
          currency: "eur",
          unit_amount: amount,
          product_data: { name: `Trésors de nos Villages — ${getFormulaLabel(formula)}` }
        }
      }],
      client_reference_id: req.user.id,
      metadata: { user_id: req.user.id, village, formula },
      success_url: `${origin}/?paiement=succes&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${origin}/?paiement=annule`
    }, {
      idempotencyKey: `checkout-${req.user.id}-${village}-${formula}-${Date.now()}`
    });

    await sql`
      INSERT INTO public.payment_orders
        (user_id, village, stripe_session_id, amount_cents, currency, status)
      VALUES (${req.user.id}, ${village}, ${session.id}, ${amount}, 'eur', 'pending')
      ON CONFLICT (stripe_session_id) DO NOTHING
    `;

    res.json({ url: session.url });
  } catch (error) {
    console.error("Create Stripe Checkout session failed:", error.message);
    res.status(500).json({ error: "Impossible de préparer le paiement. Réessaie dans un instant." });
  }
});
const allowedOrigins = process.env.SITE_ORIGIN.split(",").map((s) => s.trim()).filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    // No Origin is accepted for health checks and command-line tools.
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed by CORS"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

const adminEmails = new Set(
  process.env.ADMIN_EMAILS.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean)
);
// Verify short-lived Neon Auth JWTs. Never trust an email supplied by the browser.
const authJwks = createRemoteJWKSet(new URL(process.env.NEON_AUTH_JWKS_URL));
const authIssuer = new URL(process.env.NEON_AUTH_URL).origin;

async function getVerifiedUser(req) {
  const authorization = req.headers.authorization || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const { payload } = await jwtVerify(match[1], authJwks, { issuer: authIssuer });
  if (!payload.sub || !payload.email) return null;
  return {
    id: String(payload.sub),
    email: String(payload.email).toLowerCase(),
    name: typeof payload.name === "string" ? payload.name : ""
  };
}

async function requireUser(req, res, next) {
  try {
    const user = await getVerifiedUser(req);
    if (!user) return res.status(401).json({ error: "Connexion requise." });
    req.user = user;
    next();
  } catch (error) {
    console.error("Auth validation failed:", error.message);
    return res.status(401).json({ error: "Session non vérifiable. Reconnecte-toi." });
  }
}

function requireAdmin(req, res, next) {
  if (!adminEmails.has(req.user.email)) {
    return res.status(403).json({ error: "Accès réservé à l’administration." });
  }
  req.staffRole = "admin";
  next();
}

async function ensureTeamTables() {
  await sql`CREATE TABLE IF NOT EXISTS public.moderator_team (
    user_id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'moderator', status TEXT NOT NULL DEFAULT 'active',
    allowed_villages JSONB NOT NULL DEFAULT '[]'::jsonb,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS public.moderator_team_history (
    id BIGSERIAL PRIMARY KEY, user_id TEXT NOT NULL, email TEXT NOT NULL, action TEXT NOT NULL,
    performed_by TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`;
}
// Un compte administrateur est identifié exclusivement par ADMIN_EMAILS.
// Un modérateur doit exister dans moderator_team et ses permissions sont
// relues en base à chaque requête protégée (aucun droit implicite).
async function requireStaff(req, res, next) {
  if (adminEmails.has(req.user.email)) {
    req.staffRole = "admin";
    req.staffPermissions = ["*"];
    return next();
  }
  try {
    await ensureTeamTables();
    const rows = await sql`
      SELECT status, permissions
      FROM public.moderator_team
      WHERE email = ${req.user.email}
      LIMIT 1
    `;
    if (!rows.length) {
      return res.status(403).json({ error: "Accès réservé à l’équipe autorisée." });
    }
    if (rows[0].status !== "active") {
      return res.status(403).json({ error: "Accès modérateur suspendu." });
    }
    req.staffRole = "moderator";
    req.staffPermissions = Array.isArray(rows[0].permissions)
      ? rows[0].permissions.filter(value => typeof value === "string")
      : [];
    return next();
  } catch (error) {
    console.error("Staff permission check failed:", error.message);
    return res.status(500).json({ error: "Impossible de vérifier les autorisations de l’équipe." });
  }
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (req.staffRole === "admin") return next();
    if (!Array.isArray(req.staffPermissions) || !req.staffPermissions.includes(permission)) {
      return res.status(403).json({ error: "Cette mission ne t’a pas été attribuée par l’administration." });
    }
    return next();
  };
}

/* ===== MESSAGERIE PRIVÉE DES MEMBRES ===== */
// Chaque message est une copie liée à un seul destinataire.
// Les requêtes membres filtrent toujours sur req.user.id.
app.get("/api/mailbox", requireUser, async (req, res) => {
  try {
    const rows = await sql`
      SELECT id, title, body, category, created_at, read_at
      FROM public.member_messages
      WHERE recipient_user_id = ${req.user.id} AND deleted_at IS NULL
      ORDER BY created_at DESC
      LIMIT 100
    `;
    const unread = rows.filter(row => !row.read_at).length;
    res.set("Cache-Control", "no-store");
    res.json({ messages: rows, unread_count: unread });
  } catch (error) {
    console.error("Mailbox read failed:", error.message);
    res.status(500).json({ error: "Impossible de charger ta boîte aux lettres. Vérifie la table member_messages dans Neon." });
  }
});

app.patch("/api/mailbox/:id/read", requireUser, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Identifiant de message invalide." });
  try {
    const rows = await sql`
      UPDATE public.member_messages
      SET read_at = COALESCE(read_at, NOW())
      WHERE id = ${id} AND recipient_user_id = ${req.user.id} AND deleted_at IS NULL
      RETURNING id, read_at
    `;
    if (!rows.length) return res.status(404).json({ error: "Message introuvable." });
    res.json({ message: rows[0] });
  } catch (error) {
    console.error("Mailbox mark read failed:", error.message);
    res.status(500).json({ error: "Impossible de marquer ce message comme lu." });
  }
});

app.delete("/api/mailbox/:id", requireUser, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Identifiant de message invalide." });
  try {
    const rows = await sql`
      UPDATE public.member_messages
      SET deleted_at = NOW()
      WHERE id = ${id} AND recipient_user_id = ${req.user.id} AND deleted_at IS NULL
      RETURNING id
    `;
    if (!rows.length) return res.status(404).json({ error: "Message introuvable." });
    res.json({ deleted: true });
  } catch (error) {
    console.error("Mailbox delete failed:", error.message);
    res.status(500).json({ error: "Impossible de supprimer ce message." });
  }
});

// Liste destinée uniquement au formulaire de rédaction admin.
app.get("/api/admin/mailbox/recipients", requireUser, requireStaff, requirePermission("support"), async (_req, res) => {
  try {
    const rows = await sql`
      SELECT u.id AS user_id, u.name, u.email,
             EXISTS (
               SELECT 1 FROM public.tester_applications t
               WHERE t.user_id::text = u.id::text AND t.status = 'accepted'
             ) AS is_tester
      FROM neon_auth."user" u
      ORDER BY u.name ASC, u.email ASC
      LIMIT 1000
    `;
    res.json({ recipients: rows });
  } catch (error) {
    console.error("Admin mailbox recipients failed:", error.message);
    res.status(500).json({ error: "Impossible de charger la liste des membres." });
  }
});

app.post("/api/admin/mailbox/send", requireUser, requireStaff, requirePermission("support"), async (req, res) => {
  const title = String(req.body?.title || "").trim();
  const body = String(req.body?.body || "").trim();
  const category = String(req.body?.category || "Message de l’administration").trim().slice(0, 60);
  const audience = String(req.body?.audience || "all");
  const memberId = String(req.body?.member_id || "").trim();
  if (title.length < 3 || title.length > 160 || body.length < 2 || body.length > 8000) {
    return res.status(400).json({ error: "Le titre doit contenir 3 à 160 caractères et le message 2 à 8 000 caractères." });
  }
  if (!["all", "testers", "member"].includes(audience) || (audience === "member" && !memberId)) {
    return res.status(400).json({ error: "Choisis un destinataire valide." });
  }
  try {
    const campaignId = randomUUID();
    const inserted = await sql`
      INSERT INTO public.member_messages
        (campaign_id, recipient_user_id, sender_user_id, sender_email, title, body, category)
      SELECT ${campaignId}, u.id::text, ${req.user.id}, ${req.user.email}, ${title}, ${body}, ${category}
      FROM neon_auth."user" u
      WHERE (
        ${audience} = 'all'
        OR (${audience} = 'testers' AND EXISTS (
          SELECT 1 FROM public.tester_applications t
          WHERE t.user_id::text = u.id::text AND t.status = 'accepted'
        ))
        OR (${audience} = 'member' AND u.id::text = ${memberId})
      )
      RETURNING id
    `;
    if (!inserted.length) return res.status(404).json({ error: "Aucun destinataire trouvé pour cet envoi." });
    res.status(201).json({ sent: true, count: inserted.length, campaign_id: campaignId });
  } catch (error) {
    console.error("Admin mailbox send failed:", error.message);
    res.status(500).json({ error: "Impossible d’envoyer le message. Vérifie la migration Neon." });
  }
});

app.get("/api/admin/mailbox/history", requireUser, requireStaff, requirePermission("support"), async (_req, res) => {
  try {
    const rows = await sql`
      SELECT campaign_id, title, body, category, sender_email,
             MIN(created_at) AS created_at, COUNT(*)::int AS recipient_count,
             COUNT(*) FILTER (WHERE read_at IS NOT NULL)::int AS read_count
      FROM public.member_messages
      WHERE sender_email IS NOT NULL
      GROUP BY campaign_id, title, body, category, sender_email
      ORDER BY MIN(created_at) DESC
      LIMIT 100
    `;
    res.json({ history: rows });
  } catch (error) {
    console.error("Admin mailbox history failed:", error.message);
    res.status(500).json({ error: "Impossible de charger l’historique des envois." });
  }
});


// ── ACTUALITÉS DU SITE ──────────────────────────────────────────────────────
// Les routes d'administration sont protégées par requireUser + requireAdmin.
app.get('/api/news', async (_req, res) => {
  try {
    const rows = await sql`
      SELECT id, title, category, body, published_at
      FROM public.site_news
      WHERE is_published = TRUE AND archived_at IS NULL
      ORDER BY COALESCE(published_at, created_at) DESC
      LIMIT 50
    `;
    res.json({ news: rows });
  } catch (error) {
    console.error('Public news list failed:', error.message);
    res.status(500).json({ error: 'Impossible de charger les actualités.' });
  }
});

app.get('/api/admin/news', requireUser, requireAdmin, async (_req, res) => {
  try {
    const rows = await sql`
      SELECT id, title, category, body, is_published, published_at,
             created_at, updated_at, archived_at
      FROM public.site_news
      ORDER BY archived_at NULLS FIRST, updated_at DESC
      LIMIT 200
    `;
    res.json({ news: rows });
  } catch (error) {
    console.error('Admin news list failed:', error.message);
    res.status(500).json({ error: 'Impossible de charger les actualités.' });
  }
});

app.post('/api/admin/news', requireUser, requireAdmin, async (req, res) => {
  const title = String(req.body?.title ?? '').trim();
  const category = String(req.body?.category ?? 'Actualité').trim() || 'Actualité';
  const body = String(req.body?.body ?? '').trim();
  const publish = req.body?.is_published === true;
  if (title.length < 3 || title.length > 180 || body.length < 3 || body.length > 12000 || category.length > 80) {
    return res.status(400).json({ error: 'Titre, catégorie ou texte invalide.' });
  }
  try {
    const rows = await sql`
      INSERT INTO public.site_news (title, category, body, is_published, published_at)
      VALUES (${title}, ${category}, ${body}, ${publish}, CASE WHEN ${publish} THEN NOW() ELSE NULL END)
      RETURNING id, title, category, body, is_published, published_at, created_at, updated_at
    `;
    if (publish) {
      const campaignId = randomUUID();
      await sql`
        INSERT INTO public.member_messages
          (campaign_id, recipient_user_id, sender_user_id, sender_email, title, body, category)
        SELECT ${campaignId}, u.id::text, ${req.user.id}, ${req.user.email},
               ${'Nouvelle publication : ' + title},
               ${'Une nouvelle publication est disponible dans Informations → ' + category + '.\n\n' + body},
               'Notification'
        FROM neon_auth."user" u
      `;
    }
    res.status(201).json({ article: rows[0] });
  } catch (error) {
    console.error('Create news failed:', error.message);
    res.status(500).json({ error: 'Impossible d’enregistrer cette actualité.' });
  }
});

app.patch('/api/admin/news/:id', requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const title = String(req.body?.title ?? '').trim();
  const category = String(req.body?.category ?? 'Actualité').trim() || 'Actualité';
  const body = String(req.body?.body ?? '').trim();
  const publish = req.body?.is_published === true;
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Identifiant invalide.' });
  if (title.length < 3 || title.length > 180 || body.length < 3 || body.length > 12000 || category.length > 80) {
    return res.status(400).json({ error: 'Titre, catégorie ou texte invalide.' });
  }
  try {
    const previous = await sql`
      SELECT is_published FROM public.site_news WHERE id = ${id} AND archived_at IS NULL LIMIT 1
    `;
    const wasPublished = previous.length > 0 && previous[0].is_published === true;
    const rows = await sql`
      UPDATE public.site_news
      SET title = ${title}, category = ${category}, body = ${body},
          is_published = ${publish},
          published_at = CASE WHEN ${publish} THEN COALESCE(published_at, NOW()) ELSE NULL END,
          updated_at = NOW()
      WHERE id = ${id} AND archived_at IS NULL
      RETURNING id, title, category, body, is_published, published_at, updated_at
    `;
    if (!rows.length) return res.status(404).json({ error: 'Actualité introuvable ou archivée.' });
    if (publish && !wasPublished) {
      const campaignId = randomUUID();
      await sql`
        INSERT INTO public.member_messages
          (campaign_id, recipient_user_id, sender_user_id, sender_email, title, body, category)
        SELECT ${campaignId}, u.id::text, ${req.user.id}, ${req.user.email},
               ${'Nouvelle publication : ' + title},
               ${'Une nouvelle publication est disponible dans Informations → ' + category + '.\n\n' + body},
               'Notification'
        FROM neon_auth."user" u
      `;
    }
    res.json({ article: rows[0] });
  } catch (error) {
    console.error('Update news failed:', error.message);
    res.status(500).json({ error: 'Impossible de modifier cette actualité.' });
  }
});

app.delete('/api/admin/news/:id', requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Identifiant invalide.' });
  try {
    const rows = await sql`DELETE FROM public.site_news WHERE id = ${id} RETURNING id`;
    if (!rows.length) return res.status(404).json({ error: 'Publication introuvable.' });
    res.json({ deleted: true, id: rows[0].id });
  } catch (error) {
    console.error('Delete news failed:', error.message);
    res.status(500).json({ error: 'Impossible de supprimer cette publication.' });
  }
});

app.patch('/api/admin/news/:id/archive', requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const archived = req.body?.archived === true;
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Identifiant invalide.' });
  try {
    const rows = await sql`
      UPDATE public.site_news
      SET archived_at = CASE WHEN ${archived} THEN NOW() ELSE NULL END,
          is_published = CASE WHEN ${archived} THEN FALSE ELSE is_published END,
          updated_at = NOW()
      WHERE id = ${id}
      RETURNING id, archived_at, is_published, updated_at
    `;
    if (!rows.length) return res.status(404).json({ error: 'Actualité introuvable.' });
    res.json({ article: rows[0] });
  } catch (error) {
    console.error('Archive news failed:', error.message);
    res.status(500).json({ error: 'Impossible d’archiver cette actualité.' });
  }
});

// Cloudinary : signature créée côté serveur, le secret ne quitte jamais Render.
app.post("/api/admin/cloudinary/signature", requireUser, requireAdmin, (req, res) => {
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey = process.env.CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET;
  if (!cloudName || !apiKey || !apiSecret) {
    return res.status(503).json({ error: "Cloudinary n’est pas encore configuré dans les variables Render." });
  }
  const timestamp = Math.floor(Date.now() / 1000);
  const folder = "tresors-de-nos-villages/etapes";
  const signature = createHmac("sha1", apiSecret)
    .update(`folder=${folder}&timestamp=${timestamp}`)
    .digest("hex");
  return res.json({ cloud_name: cloudName, api_key: apiKey, timestamp, folder, signature });
});


// ===== STATISTIQUES DE VISITE — sans collecte d'adresse IP =====
async function getOptionalUser(req) {
  const authorization = req.headers.authorization || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  try {
    const { payload } = await jwtVerify(match[1], authJwks, { issuer: authIssuer });
    if (!payload.sub || !payload.email) return null;
    return { id: String(payload.sub), email: String(payload.email).toLowerCase() };
  } catch {
    return null;
  }
}

app.post("/api/analytics/heartbeat", async (req, res) => {
  const visitorKey = String(req.body?.visitor_key || "");
  const pagePath = String(req.body?.page_path || "/").slice(0, 300);
  const village = String(req.body?.village || "").slice(0, 100) || null;
  const formula = String(req.body?.formula || "").slice(0, 50) || null;

  // Random browser session key only; do not accept email, name, or IP as identity.
  if (!/^[a-zA-Z0-9_-]{20,100}$/.test(visitorKey)) {
    return res.status(400).json({ error: "Identifiant de visite invalide." });
  }

  try {
    const user = await getOptionalUser(req);
    await sql`
      INSERT INTO public.site_visitors
        (visitor_key, user_id, page_path, village, formula, first_seen, last_seen)
      VALUES
        (${visitorKey}, ${user?.id || null}, ${pagePath}, ${village}, ${formula}, NOW(), NOW())
      ON CONFLICT (visitor_key) DO UPDATE SET
        user_id = COALESCE(EXCLUDED.user_id, public.site_visitors.user_id),
        page_path = EXCLUDED.page_path,
        village = COALESCE(EXCLUDED.village, public.site_visitors.village),
        formula = COALESCE(EXCLUDED.formula, public.site_visitors.formula),
        last_seen = NOW()
    `;
    res.json({ ok: true });
  } catch (error) {
    console.error("Visitor heartbeat failed:", error.message);
    res.status(500).json({ error: "Impossible d'enregistrer la visite." });
  }
});

app.get("/api/admin/analytics", requireUser, requireAdmin, async (_req, res) => {
  try {
    const totals = await sql`
      SELECT
        COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '5 minutes')::int AS active_visitors,
        COUNT(*) FILTER (
          WHERE last_seen > NOW() - INTERVAL '5 minutes' AND user_id IS NOT NULL
        )::int AS active_members,
        COUNT(*) FILTER (
          WHERE last_seen > NOW() - INTERVAL '5 minutes' AND user_id IS NULL
        )::int AS active_anonymous,
        COUNT(*) FILTER (WHERE first_seen >= NOW() - INTERVAL '24 hours')::int AS visits_24h
      FROM public.site_visitors
    `;
    const recent = await sql`
      SELECT
        CASE WHEN v.user_id IS NULL THEN 'Visiteur anonyme'
             ELSE COALESCE(p.pseudo, 'Explorateur inscrit')
        END AS visitor_label,
        (v.user_id IS NOT NULL) AS is_member,
        v.page_path, v.village, v.formula, v.first_seen, v.last_seen
      FROM public.site_visitors v
      LEFT JOIN public.explorer_profiles p ON p.user_id = v.user_id
      ORDER BY v.last_seen DESC
      LIMIT 30
    `;
    const daily = await sql`
      SELECT d.day::date::text AS day, COUNT(v.visitor_key)::int AS visits
      FROM generate_series(CURRENT_DATE - 6, CURRENT_DATE, INTERVAL '1 day') AS d(day)
      LEFT JOIN public.site_visitors v
        ON v.first_seen >= d.day
       AND v.first_seen < d.day + INTERVAL '1 day'
      GROUP BY d.day
      ORDER BY d.day
    `;
    const village_visits = await sql`
      SELECT village, COUNT(*)::int AS visits
      FROM public.site_visitors
      WHERE village IS NOT NULL AND BTRIM(village) <> ''
      GROUP BY village
      ORDER BY visits DESC
      LIMIT 10
    `;
    res.json({ totals: totals[0] || {}, recent, daily, village_visits });
  } catch (error) {
    console.error("Read site analytics failed:", error.message);
    res.status(500).json({ error: "Impossible de charger les statistiques." });
  }
});

app.get("/health", (_req, res) => res.json({ ok: true, service: "tresors-api" }));

app.get("/api/admin/me", requireUser, requireStaff, (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({
    ok: true,
    role: req.staffRole,
    permissions: req.staffPermissions || [],
    user: { id: req.user.id, email: req.user.email, name: req.user.name }
  });
});

/* ===== GESTION DES MODÉRATEURS ET DE LEURS AUTORISATIONS ===== */
app.get("/api/admin/team", requireUser, requireAdmin, async (_req,res)=>{
  try { await ensureTeamTables(); const members=await sql`SELECT user_id,email,name,role,status,allowed_villages,permissions,created_at,updated_at FROM public.moderator_team ORDER BY created_at DESC`; res.set("Cache-Control","no-store"); res.json({members}); }
  catch(error){console.error("Team list failed:",error.message);res.status(500).json({error:"Impossible de charger l'équipe."});}
});
app.post("/api/admin/team", requireUser, requireAdmin, async(req,res)=>{
  const email=String(req.body?.email||"").trim().toLowerCase();
  const villages=Array.isArray(req.body?.allowed_villages)?req.body.allowed_villages.filter(x=>typeof x==="string").slice(0,100):[];
  const allowed=new Set(["support","map","puzzle","leaderboard","reports","testers","news","adventures"]);
  const permissions=Array.isArray(req.body?.permissions)?[...new Set(req.body.permissions.filter(x=>allowed.has(x)))]:[];
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>180)return res.status(400).json({error:"Adresse e-mail invalide."});
  try{await ensureTeamTables();const rows=await sql`INSERT INTO public.moderator_team(user_id,email,name,role,status,allowed_villages,permissions,created_by,updated_at) VALUES(${`email:${email}`},${email},'', 'moderator','active',${JSON.stringify(villages)}::jsonb,${JSON.stringify(permissions)}::jsonb,${req.user.email},NOW()) ON CONFLICT(email) DO UPDATE SET status='active',allowed_villages=EXCLUDED.allowed_villages,permissions=EXCLUDED.permissions,updated_at=NOW() RETURNING user_id,email,name,role,status,allowed_villages,permissions,created_at,updated_at`;await sql`INSERT INTO public.moderator_team_history(user_id,email,action,performed_by) VALUES(${rows[0].user_id},${email},'Modérateur ajouté ou réactivé',${req.user.email})`;res.json({member:rows[0]});}
  catch(error){console.error("Team add failed:",error.message);res.status(500).json({error:"Impossible d'ajouter le modérateur."});}
});
app.patch("/api/admin/team/:id", requireUser, requireAdmin, async(req,res)=>{
  const id=String(req.params.id||"");const status=req.body?.status;const allowedStatuses=["active","suspended"];
  const permissionKeys=new Set(["support","map","puzzle","leaderboard","reports","testers","news","adventures"]);
  const hasPermissions=Array.isArray(req.body?.permissions);const hasVillages=Array.isArray(req.body?.allowed_villages);
  if(status!==undefined&&!allowedStatuses.includes(status))return res.status(400).json({error:"Statut invalide."});
  if(hasPermissions&&req.body.permissions.some(x=>!permissionKeys.has(x)))return res.status(400).json({error:"Autorisation inconnue."});
  try{await ensureTeamTables();let rows;
    if(status!==undefined&&hasPermissions&&hasVillages) rows=await sql`UPDATE public.moderator_team SET status=${status},permissions=${JSON.stringify(req.body.permissions)}::jsonb,allowed_villages=${JSON.stringify(req.body.allowed_villages)}::jsonb,updated_at=NOW() WHERE user_id=${id} RETURNING user_id,email,status,permissions,allowed_villages`;
    else if(status!==undefined) rows=await sql`UPDATE public.moderator_team SET status=${status},updated_at=NOW() WHERE user_id=${id} RETURNING user_id,email,status,permissions,allowed_villages`;
    else if(hasPermissions&&hasVillages) rows=await sql`UPDATE public.moderator_team SET permissions=${JSON.stringify(req.body.permissions)}::jsonb,allowed_villages=${JSON.stringify(req.body.allowed_villages)}::jsonb,updated_at=NOW() WHERE user_id=${id} RETURNING user_id,email,status,permissions,allowed_villages`;
    else if(hasPermissions) rows=await sql`UPDATE public.moderator_team SET permissions=${JSON.stringify(req.body.permissions)}::jsonb,updated_at=NOW() WHERE user_id=${id} RETURNING user_id,email,status,permissions,allowed_villages`;
    else if(hasVillages) rows=await sql`UPDATE public.moderator_team SET allowed_villages=${JSON.stringify(req.body.allowed_villages)}::jsonb,updated_at=NOW() WHERE user_id=${id} RETURNING user_id,email,status,permissions,allowed_villages`;
    else return res.status(400).json({error:"Aucune modification fournie."});
    if(!rows.length)return res.status(404).json({error:"Modérateur introuvable."});
    await sql`INSERT INTO public.moderator_team_history(user_id,email,action,performed_by) VALUES(${rows[0].user_id},${rows[0].email},${status!==undefined?`Statut : ${status}`:'Autorisations modifiées'},${req.user.email})`;
    res.json({member:rows[0]});
  }catch(error){console.error("Team update failed:",error.message);res.status(500).json({error:"Impossible d'enregistrer les autorisations."});}
});
app.get("/api/admin/team/:id/history",requireUser,requireAdmin,async(req,res)=>{try{await ensureTeamTables();const history=await sql`SELECT action,performed_by,created_at FROM public.moderator_team_history WHERE user_id=${String(req.params.id)} ORDER BY created_at DESC LIMIT 100`;res.json({history});}catch(error){console.error("Team history failed:",error.message);res.status(500).json({error:"Historique indisponible."});}});


/* ===== STATUT PUBLIC DU SITE ===== */
app.get("/api/site-status", async (_req, res) => {
  try {
    const rows = await sql`
      SELECT status, message, banner_enabled, notify_members, schedule_enabled,
             starts_at, ends_at, updated_at
      FROM public.site_status_settings WHERE id = 1
    `;
    const row = rows[0] || { status: "online", message: "", banner_enabled: false, notify_members: false, schedule_enabled: false };
    const now = Date.now();
    let effectiveStatus = row.status || "online";
    if (row.schedule_enabled) {
      const start = row.starts_at ? new Date(row.starts_at).getTime() : null;
      const end = row.ends_at ? new Date(row.ends_at).getTime() : null;
      if ((start && now < start) || (end && now > end)) effectiveStatus = "online";
    }
    res.set("Cache-Control", "no-store");
    res.json({ ...row, status: effectiveStatus });
  } catch (error) {
    console.error("Public site status failed:", error.message);
    res.json({ status: "online", message: "", banner_enabled: false, notify_members: false, schedule_enabled: false });
  }
});

app.get("/api/admin/site-status", requireUser, requireAdmin, async (_req, res) => {
  try {
    const rows = await sql`SELECT status, message, banner_enabled, notify_members, schedule_enabled, starts_at, ends_at, updated_at FROM public.site_status_settings WHERE id = 1`;
    res.json(rows[0] || { status: "online", message: "", banner_enabled: true, notify_members: false, schedule_enabled: false, starts_at: null, ends_at: null });
  } catch (error) {
    console.error("Admin site status read failed:", error.message);
    res.status(500).json({ error: "Impossible de charger le statut du site. Exécute d’abord la migration SQL." });
  }
});

app.put("/api/admin/site-status", requireUser, requireAdmin, async (req, res) => {
  const allowed = new Set(["online", "maintenance", "update", "works", "suspended"]);
  const status = String(req.body?.status || "online");
  const message = String(req.body?.message || "").trim().slice(0, 500);
  const bannerEnabled = req.body?.banner_enabled !== false;
  const notifyMembers = req.body?.notify_members === true;
  const scheduleEnabled = req.body?.schedule_enabled === true;
  const startsAt = req.body?.starts_at || null;
  const endsAt = req.body?.ends_at || null;
  if (!allowed.has(status)) return res.status(400).json({ error: "Statut non reconnu." });
  if (scheduleEnabled && (!startsAt || !endsAt || new Date(endsAt) <= new Date(startsAt))) {
    return res.status(400).json({ error: "La période programmée est invalide." });
  }
  try {
    const rows = await sql`
      INSERT INTO public.site_status_settings
        (id, status, message, banner_enabled, notify_members, schedule_enabled, starts_at, ends_at, updated_by, updated_at)
      VALUES
        (1, ${status}, ${message}, ${bannerEnabled}, ${notifyMembers}, ${scheduleEnabled},
         ${startsAt ? new Date(startsAt).toISOString() : null},
         ${endsAt ? new Date(endsAt).toISOString() : null},
         ${req.user.email}, NOW())
      ON CONFLICT (id) DO UPDATE SET
        status = EXCLUDED.status,
        message = EXCLUDED.message,
        banner_enabled = EXCLUDED.banner_enabled,
        notify_members = EXCLUDED.notify_members,
        schedule_enabled = EXCLUDED.schedule_enabled,
        starts_at = EXCLUDED.starts_at,
        ends_at = EXCLUDED.ends_at,
        updated_by = EXCLUDED.updated_by,
        updated_at = NOW()
      RETURNING status, message, banner_enabled, notify_members, schedule_enabled, starts_at, ends_at, updated_at
    `;
    res.json(rows[0]);
  } catch (error) {
    console.error("Admin site status save failed:", error.message);
    res.status(500).json({ error: "Impossible d’enregistrer le statut. Vérifie que la migration SQL a été exécutée." });
  }
});


/* ===== GESTION DES VILLAGES ===== */
// Liste publique : utilisée par la carte Explorer. Les villages ne sont jamais modifiables ici.
app.get("/api/villages", async (_req, res) => {
  try {
    const villages = await sql`
      SELECT id, name, slug, postal_code, description, status,
             latitude, longitude, photo_url, created_at, updated_at
      FROM public.villages
      ORDER BY name ASC
    `;
    res.json({ villages });
  } catch (error) {
    console.error("Public villages list failed:", error.message);
    res.status(500).json({ error: "Impossible de charger la carte des villages." });
  }
});

app.get("/api/admin/villages", requireUser, requireAdmin, async (_req, res) => {
  try {
    const villages = await sql`
      SELECT id, name, slug, postal_code, description, status,
             latitude, longitude, photo_url, created_at, updated_at
      FROM public.villages
      ORDER BY name ASC
    `;
    res.json({ villages });
  } catch (error) {
    console.error("Admin villages list failed:", error.message);
    res.status(500).json({ error: "Impossible de charger les villages. Vérifie que la table villages a été créée dans Neon." });
  }
});

const ADMIN_VILLAGE_STATUSES = new Set([
  "pending_confirmation", "in_progress", "available", "suspended", "updating"
]);
function readVillagePayload(body = {}) {
  const name = String(body.name ?? "").trim();
  const slug = String(body.slug ?? "").trim().toLowerCase();
  const postalCode = String(body.postal_code ?? "").trim();
  const description = String(body.description ?? "").trim();
  const status = String(body.status ?? "pending_confirmation");
  const photoUrl = String(body.photo_url ?? "").trim();
  const latitude = body.latitude === null || body.latitude === "" || body.latitude === undefined ? null : Number(body.latitude);
  const longitude = body.longitude === null || body.longitude === "" || body.longitude === undefined ? null : Number(body.longitude);

  if (name.length < 2 || name.length > 150) return { error: "Le nom doit contenir entre 2 et 150 caractères." };
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug) || slug.length > 100) return { error: "Identifiant du village invalide. Utilise des minuscules et des tirets." };
  if (postalCode.length > 10 || description.length > 3000 || !ADMIN_VILLAGE_STATUSES.has(status)) return { error: "Informations du village invalides." };
  if (latitude !== null && (!Number.isFinite(latitude) || latitude < -90 || latitude > 90)) return { error: "La latitude GPS doit être comprise entre -90 et 90." };
  if (longitude !== null && (!Number.isFinite(longitude) || longitude < -180 || longitude > 180)) return { error: "La longitude GPS doit être comprise entre -180 et 180." };
  if (photoUrl.length > 1000 || (photoUrl && !/^https?:\/\//i.test(photoUrl))) return { error: "L’adresse de la photo doit commencer par https:// ou http://." };
  return { value: { name, slug, postalCode, description, status, latitude, longitude, photoUrl: photoUrl || null } };
}

app.post("/api/admin/villages", requireUser, requireAdmin, async (req, res) => {
  const parsed = readVillagePayload(req.body);
  if (parsed.error) return res.status(400).json({ error: parsed.error });
  const { name, slug, postalCode, description, status, latitude, longitude, photoUrl } = parsed.value;
  try {
    const rows = await sql`
      INSERT INTO public.villages
        (name, slug, postal_code, description, status, latitude, longitude, photo_url)
      VALUES
        (${name}, ${slug}, ${postalCode || null}, ${description}, ${status},
         ${latitude}, ${longitude}, ${photoUrl})
      RETURNING id, name, slug, postal_code, description, status,
                latitude, longitude, photo_url, created_at, updated_at
    `;
    res.status(201).json({ village: rows[0] });
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "Ce village existe déjà." });
    console.error("Create village failed:", error.message);
    res.status(500).json({ error: "Impossible d'enregistrer le village." });
  }
});

app.patch("/api/admin/villages/:id", requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Identifiant de village invalide." });
  const parsed = readVillagePayload(req.body);
  if (parsed.error) return res.status(400).json({ error: parsed.error });
  const { name, slug, postalCode, description, status, latitude, longitude, photoUrl } = parsed.value;
  try {
    const rows = await sql`
      UPDATE public.villages
      SET name = ${name}, slug = ${slug}, postal_code = ${postalCode || null},
          description = ${description}, status = ${status},
          latitude = ${latitude}, longitude = ${longitude}, photo_url = ${photoUrl},
          updated_at = NOW()
      WHERE id = ${id}
      RETURNING id, name, slug, postal_code, description, status,
                latitude, longitude, photo_url, created_at, updated_at
    `;
    if (!rows.length) return res.status(404).json({ error: "Village introuvable." });
    res.json({ village: rows[0] });
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "Cet identifiant est déjà utilisé par un autre village." });
    console.error("Update village failed:", error.message);
    res.status(500).json({ error: "Impossible de modifier le village." });
  }
});

app.delete("/api/admin/villages/:id", requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Identifiant de village invalide." });
  try {
    const rows = await sql`DELETE FROM public.villages WHERE id = ${id} RETURNING id`;
    if (!rows.length) return res.status(404).json({ error: "Village introuvable." });
    res.json({ deleted: true, id: rows[0].id });
  } catch (error) {
    console.error("Delete village failed:", error.message);
    res.status(500).json({ error: "Impossible de supprimer ce village. Vérifie qu’aucune aventure ne lui est rattachée." });
  }
});

/* ===== CANDIDATURES TESTEURS ===== */
// Un utilisateur connecté peut déposer ou consulter sa demande avec son compte Neon existant.
app.get("/api/testers/me", requireUser, async (req, res) => {
  try {
    const rows = await sql`
      SELECT id, motivation, adult_confirmation, status, submitted_at, reviewed_at
      FROM public.tester_applications
      WHERE user_id = ${req.user.id}
      LIMIT 1
    `;
    res.json({ application: rows[0] || null });
  } catch (error) {
    console.error("Read tester application failed:", error.message);
    res.status(500).json({ error: "Impossible de charger ta demande de testeur." });
  }
});

app.post("/api/testers/apply", requireUser, async (req, res) => {
  const motivation = String(req.body?.motivation ?? "").trim();
  const adultConfirmation = req.body?.adult_confirmation === true;
  if (motivation.length > 1000) return res.status(400).json({ error: "Le message ne doit pas dépasser 1 000 caractères." });
  if (!adultConfirmation) return res.status(400).json({ error: "La confirmation d'un adulte ou responsable légal est nécessaire." });
  try {
    const rows = await sql`
      INSERT INTO public.tester_applications AS existing (user_id, motivation, adult_confirmation, status, submitted_at, reviewed_at, reviewed_by, updated_at)
      VALUES (${req.user.id}, ${motivation}, ${adultConfirmation}, 'pending', NOW(), NULL, NULL, NOW())
      ON CONFLICT (user_id) DO UPDATE SET
        motivation = EXCLUDED.motivation,
        adult_confirmation = EXCLUDED.adult_confirmation,
        status = CASE WHEN existing.status = 'accepted' THEN 'accepted' ELSE 'pending' END,
        submitted_at = CASE WHEN existing.status = 'accepted' THEN existing.submitted_at ELSE NOW() END,
        reviewed_at = CASE WHEN existing.status = 'accepted' THEN existing.reviewed_at ELSE NULL END,
        reviewed_by = CASE WHEN existing.status = 'accepted' THEN existing.reviewed_by ELSE NULL END,
        updated_at = NOW()
      RETURNING id, motivation, adult_confirmation, status, submitted_at, reviewed_at
    `;
    res.status(201).json({ application: rows[0] });
  } catch (error) {
    console.error("Submit tester application failed:", error.message);
    res.status(500).json({ error: "Impossible d'enregistrer ta demande de testeur." });
  }
});

app.get("/api/admin/testers", requireUser, requireAdmin, async (_req, res) => {
  try {
    const applications = await sql`
      SELECT a.id, a.user_id, u.name, u.email, a.motivation,
             a.adult_confirmation, a.status, a.submitted_at,
             a.reviewed_at, a.reviewed_by
      FROM public.tester_applications a
      LEFT JOIN neon_auth."user" u ON u.id::text = a.user_id::text
      ORDER BY CASE a.status WHEN 'pending' THEN 0 WHEN 'accepted' THEN 1 ELSE 2 END,
               a.submitted_at DESC
      LIMIT 500
    `;
    res.json({ applications, count: applications.length });
  } catch (error) {
    console.error("Admin tester applications failed:", error.message);
    res.status(500).json({ error: "Impossible de charger les demandes de testeurs. Vérifie que la table tester_applications a été créée dans Neon." });
  }
});

app.patch("/api/admin/testers/:id", requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const status = String(req.body?.status ?? "");
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Identifiant de demande invalide." });
  if (!['accepted', 'rejected', 'pending'].includes(status)) return res.status(400).json({ error: "Statut de demande invalide." });
  try {
    const rows = await sql`
      UPDATE public.tester_applications
      SET status = ${status},
          reviewed_at = CASE WHEN ${status} = 'pending' THEN NULL ELSE NOW() END,
          reviewed_by = CASE WHEN ${status} = 'pending' THEN NULL ELSE ${req.user.email} END,
          updated_at = NOW()
      WHERE id = ${id}
      RETURNING id, user_id, status, reviewed_at, reviewed_by
    `;
    if (!rows.length) return res.status(404).json({ error: "Demande introuvable." });
    res.json({ application: rows[0] });
  } catch (error) {
    console.error("Update tester application failed:", error.message);
    res.status(500).json({ error: "Impossible de mettre à jour cette demande." });
  }
});


/* ===== ESPACE PERSONNEL ET MISSIONS DES TESTEURS ===== */
async function hasAcceptedTesterAccess(userId, villageSlug, levelKey) {
  const rows = await sql`
    SELECT 1
    FROM public.tester_applications t
    JOIN public.tester_access a ON a.user_id = t.user_id
    WHERE t.user_id = ${userId} AND t.status = 'accepted'
      AND a.village_slug = ${villageSlug} AND a.formula = ${levelKey}
    LIMIT 1
  `;
  return rows.length > 0;
}

// Missions issues uniquement des villages/niveaux attribués à ce compte.
// Les aventures non publiées restent accessibles au testeur autorisé, jamais aux autres joueurs.
app.get("/api/testers/missions", requireUser, async (req, res) => {
  try {
    const rows = await sql`
      SELECT a.id AS adventure_id, a.title, a.description, a.village_slug,
             v.name AS village_name, a.level_key,
             COALESCE(l.display_name, a.level_key) AS level_name,
             COUNT(DISTINCT s.id)::int AS total_steps,
             COUNT(DISTINCT uv.step_id)::int AS validated_steps,
             COALESCE(l.star_count, 0)::int AS total_stars,
             BOOL_OR(a.is_published) AS is_published
      FROM public.tester_access ta
      JOIN public.tester_applications t ON t.user_id = ta.user_id AND t.status = 'accepted'
      LEFT JOIN public.villages v ON v.slug = ta.village_slug
      LEFT JOIN public.adventures a ON a.village_slug = ta.village_slug AND a.level_key = ta.formula
      LEFT JOIN public.village_level_settings l ON l.village_slug = ta.village_slug AND l.level_key = ta.formula
      LEFT JOIN public.adventure_steps s ON s.adventure_id = a.id
      LEFT JOIN public.user_step_validations uv ON uv.step_id = s.id AND uv.adventure_id = a.id AND uv.user_id = ${req.user.id}
      WHERE ta.user_id = ${req.user.id}
      GROUP BY a.id, a.title, a.description, a.village_slug, v.name, a.level_key, l.display_name, l.star_count, ta.village_slug, ta.formula
      ORDER BY v.name ASC, level_name ASC, a.id ASC
    `;
    res.json({ missions: rows.map(row => ({
      ...row,
      total_steps: Number(row.total_steps || 0),
      validated_steps: Number(row.validated_steps || 0),
      total_stars: Number(row.total_stars || 0),
      completed: Number(row.total_steps || 0) > 0 && Number(row.validated_steps || 0) >= Number(row.total_steps || 0),
      state: row.adventure_id ? (row.is_published ? 'Parcours en ligne' : 'Parcours à tester') : 'Parcours en préparation'
    })) });
  } catch (error) {
    console.error("Read tester missions failed:", error.message);
    res.status(500).json({ error: "Impossible de charger tes missions de test." });
  }
});

/* ===== VALIDATION DES NIVEAUX DE TEST (PHASE 4) ===== */
const TESTER_REVIEW_STATUSES = new Set(["en_attente", "valide", "a_corriger"]);

// Un testeur peut demander la validation uniquement après avoir terminé toutes les étapes
// de l'aventure qui lui a été attribuée. L'identité vient toujours du jeton authentifié.
app.post("/api/testers/level-review", requireUser, async (req, res) => {
  const village = String(req.body?.village || "").trim().toLowerCase();
  const formula = String(req.body?.formula || "").trim().toLowerCase();
  const report = String(req.body?.report || "").trim();
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(village) || !TESTER_LEVELS.has(formula) || report.length > 3000) {
    return res.status(400).json({ error: "Les informations du bilan sont invalides." });
  }
  try {
    const access = await sql`
      SELECT 1 FROM public.tester_applications t
      JOIN public.tester_access ta ON ta.user_id = t.user_id
      WHERE t.user_id = ${req.user.id} AND t.status = 'accepted'
        AND ta.village_slug = ${village} AND ta.formula = ${formula}
      LIMIT 1
    `;
    if (!access.length) return res.status(403).json({ error: "Ce village et ce niveau ne te sont pas attribués." });

    const adventures = await sql`
      SELECT id FROM public.adventures
      WHERE village_slug = ${village} AND level_key = ${formula}
      ORDER BY id DESC LIMIT 1
    `;
    if (!adventures.length) return res.status(409).json({ error: "Le parcours n'est pas encore disponible pour ce niveau." });
    const adventureId = adventures[0].id;
    const counts = await sql`
      SELECT COUNT(DISTINCT s.id)::int AS total_steps,
             COUNT(DISTINCT uv.step_id)::int AS validated_steps
      FROM public.adventure_steps s
      LEFT JOIN public.user_step_validations uv
        ON uv.step_id = s.id AND uv.adventure_id = s.adventure_id AND uv.user_id = ${req.user.id}
      WHERE s.adventure_id = ${adventureId}
    `;
    const total = Number(counts[0]?.total_steps || 0);
    const done = Number(counts[0]?.validated_steps || 0);
    if (total < 1 || done < total) {
      return res.status(409).json({ error: `Le niveau n'est pas terminé : ${done}/${total} étapes validées.` });
    }
    const pending = await sql`
      SELECT id FROM public.tester_level_reviews
      WHERE user_id = ${req.user.id} AND village_slug = ${village} AND formula = ${formula}
        AND status = 'en_attente' LIMIT 1
    `;
    if (pending.length) return res.status(409).json({ error: "Une demande de validation est déjà en attente." });
    const approved = await sql`
      SELECT id FROM public.tester_level_reviews
      WHERE user_id = ${req.user.id} AND village_slug = ${village} AND formula = ${formula}
        AND status = 'valide' LIMIT 1
    `;
    if (approved.length) return res.status(409).json({ error: "Ce niveau est déjà validé par l'administration." });
    const rows = await sql`
      INSERT INTO public.tester_level_reviews
        (user_id, village_slug, formula, adventure_id, report, status)
      VALUES (${req.user.id}, ${village}, ${formula}, ${adventureId}, ${report || null}, 'en_attente')
      RETURNING id, village_slug, formula, report, status, created_at
    `;
    res.status(201).json({ review: rows[0] });
  } catch (error) {
    console.error("Create tester level review failed:", error.message);
    res.status(500).json({ error: "Impossible d'envoyer la demande de validation." });
  }
});

app.get("/api/testers/level-reviews/mine", requireUser, async (req, res) => {
  try {
    const rows = await sql`
      SELECT r.id, r.village_slug, v.name AS village_name, r.formula, r.report,
             r.status, r.admin_note, r.created_at, r.reviewed_at
      FROM public.tester_level_reviews r
      LEFT JOIN public.villages v ON v.slug = r.village_slug
      WHERE r.user_id = ${req.user.id}
      ORDER BY r.created_at DESC LIMIT 100
    `;
    res.json({ reviews: rows });
  } catch (error) {
    console.error("Read own tester level reviews failed:", error.message);
    res.status(500).json({ error: "Impossible de charger tes demandes de validation." });
  }
});

app.get("/api/admin/tester-level-reviews", requireUser, requireAdmin, async (_req, res) => {
  try {
    const rows = await sql`
      SELECT r.id, r.user_id, u.name AS tester_name, u.email AS tester_email,
             r.village_slug, v.name AS village_name, r.formula, r.report,
             r.status, r.admin_note, r.created_at, r.reviewed_at
      FROM public.tester_level_reviews r
      LEFT JOIN neon_auth."user" u ON u.id::text = r.user_id::text
      LEFT JOIN public.villages v ON v.slug = r.village_slug
      ORDER BY CASE WHEN r.status = 'en_attente' THEN 0 ELSE 1 END, r.created_at DESC
      LIMIT 500
    `;
    res.json({ reviews: rows, count: rows.length });
  } catch (error) {
    console.error("Admin list tester level reviews failed:", error.message);
    res.status(500).json({ error: "Impossible de charger les demandes de validation." });
  }
});

app.patch("/api/admin/tester-level-reviews/:id", requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const status = String(req.body?.status || "");
  const adminNote = String(req.body?.admin_note || "").trim();
  if (!Number.isSafeInteger(id) || id < 1 || !["valide", "a_corriger"].includes(status) || adminNote.length > 3000) {
    return res.status(400).json({ error: "Décision ou commentaire invalide." });
  }
  try {
    const current = await sql`
      SELECT id, user_id, adventure_id FROM public.tester_level_reviews
      WHERE id = ${id} AND status = 'en_attente' LIMIT 1
    `;
    if (!current.length) return res.status(404).json({ error: "Demande introuvable ou déjà traitée." });
    const rows = await sql`
      UPDATE public.tester_level_reviews
      SET status = ${status}, admin_note = ${adminNote || null},
          reviewed_at = NOW(), reviewed_by = ${req.user.email}, updated_at = NOW()
      WHERE id = ${id} AND status = 'en_attente'
      RETURNING id, status, admin_note, reviewed_at
    `;
    if (!rows.length) return res.status(404).json({ error: "Demande introuvable ou déjà traitée." });
    // En cas de correction demandée, on remet à zéro les validations d'étapes
    // de cette aventure pour que le testeur puisse réellement refaire son parcours.
    if (status === "a_corriger") {
      await sql`
        DELETE FROM public.user_step_validations
        WHERE user_id = ${current[0].user_id} AND adventure_id = ${current[0].adventure_id}
      `;
    }
    res.json({ review: rows[0], progress_reset: status === "a_corriger" });
  } catch (error) {
    console.error("Admin review tester level failed:", error.message);
    res.status(500).json({ error: "Impossible d'enregistrer cette décision." });
  }
});

/* ===== ACCES ET RETOURS DES TESTEURS ===== */
// Les accès testeurs sont séparés des achats : ils ne donnent aucun droit payant.
const TESTER_LEVELS = new Set([
  "enfant", "facile", "famille", "moyen", "difficile", "extreme", "nuit"
]);
const TESTER_FEEDBACK_CATEGORIES = new Set(["bug", "idee", "experience", "autre"]);
const TESTER_FEEDBACK_STATUSES = new Set(["en_attente", "en_cours_etude", "corrige", "refuse"]);

// Un testeur ne voit que ses propres accès.
app.get("/api/testers/access", requireUser, async (req, res) => {
  try {
    const rows = await sql`
      SELECT a.id, a.village_slug, v.name AS village_name,
             a.formula, a.assigned_at
      FROM public.tester_access a
      LEFT JOIN public.villages v ON v.slug = a.village_slug
      JOIN public.tester_applications t
        ON t.user_id = a.user_id AND t.status = 'accepted'
      WHERE a.user_id = ${req.user.id}
      ORDER BY v.name ASC, a.formula ASC
    `;
    res.json({ access: rows });
  } catch (error) {
    console.error("Read tester access failed:", error.message);
    res.status(500).json({ error: "Impossible de charger tes accès testeur." });
  }
});

// Un testeur ne peut envoyer un retour que pour un village/niveau qui lui est attribué.
app.post("/api/testers/feedback", requireUser, async (req, res) => {
  const village = String(req.body?.village || "").trim().toLowerCase();
  const formula = String(req.body?.formula || "").trim().toLowerCase();
  const category = String(req.body?.category || "experience").trim().toLowerCase();
  const message = String(req.body?.message || "").trim();

  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(village) ||
      !TESTER_LEVELS.has(formula) ||
      !TESTER_FEEDBACK_CATEGORIES.has(category) ||
      message.length < 5 || message.length > 3000) {
    return res.status(400).json({ error: "Les informations du retour sont invalides." });
  }
  try {
    const allowed = await sql`
      SELECT 1
      FROM public.tester_applications t
      JOIN public.tester_access a ON a.user_id = t.user_id
      WHERE t.user_id = ${req.user.id}
        AND t.status = 'accepted'
        AND a.village_slug = ${village}
        AND a.formula = ${formula}
      LIMIT 1
    `;
    if (!allowed.length) {
      return res.status(403).json({ error: "Tu n'as pas accès à ce village et à ce niveau de test." });
    }
    const rows = await sql`
      INSERT INTO public.tester_feedback
        (user_id, village_slug, formula, category, message)
      VALUES (${req.user.id}, ${village}, ${formula}, ${category}, ${message})
      RETURNING id, village_slug, formula, category, message, status, created_at
    `;
    res.status(201).json({ feedback: rows[0] });
  } catch (error) {
    console.error("Create tester feedback failed:", error.message);
    res.status(500).json({ error: "Impossible d'enregistrer ton retour." });
  }
});

// Historique strictement personnel : aucun retour d'un autre testeur n'est renvoyé.
app.get("/api/testers/feedback/mine", requireUser, async (req, res) => {
  try {
    const rows = await sql`
      SELECT id, village_slug, formula, category, message, status, admin_response, responded_at, created_at, updated_at
      FROM public.tester_feedback
      WHERE user_id = ${req.user.id}
      ORDER BY created_at DESC
      LIMIT 100
    `;
    res.json({ feedback: rows });
  } catch (error) {
    console.error("Read own tester feedback failed:", error.message);
    res.status(500).json({ error: "Impossible de charger tes retours." });
  }
});

// Vue admin des accès attribués.
app.get("/api/admin/testers/:userId/access", requireUser, requireAdmin, async (req, res) => {
  const userId = String(req.params.userId || "").trim();
  if (!userId || userId.length > 200) return res.status(400).json({ error: "Compte testeur invalide." });
  try {
    const rows = await sql`
      SELECT a.id, a.user_id, a.village_slug, v.name AS village_name,
             a.formula, a.assigned_at, a.assigned_by
      FROM public.tester_access a
      LEFT JOIN public.villages v ON v.slug = a.village_slug
      WHERE a.user_id = ${userId}
      ORDER BY v.name ASC, a.formula ASC
    `;
    res.json({ access: rows });
  } catch (error) {
    console.error("Admin read tester access failed:", error.message);
    res.status(500).json({ error: "Impossible de charger les accès de ce testeur." });
  }
});

// L'admin attribue ou retire un couple village/niveau à un testeur accepté.
app.put("/api/admin/testers/:userId/access", requireUser, requireAdmin, async (req, res) => {
  const userId = String(req.params.userId || "").trim();
  const village = String(req.body?.village || "").trim().toLowerCase();
  const formula = String(req.body?.formula || "").trim().toLowerCase();
  const enabled = req.body?.enabled;
  if (!userId || userId.length > 200 ||
      !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(village) ||
      !TESTER_LEVELS.has(formula) || typeof enabled !== "boolean") {
    return res.status(400).json({ error: "Attribution invalide." });
  }
  try {
    const accepted = await sql`
      SELECT id FROM public.tester_applications
      WHERE user_id = ${userId} AND status = 'accepted'
      LIMIT 1
    `;
    if (!accepted.length) {
      return res.status(409).json({ error: "Ce compte doit d'abord avoir une candidature acceptée." });
    }
    const villageRows = await sql`
      SELECT slug FROM public.villages WHERE slug = ${village} LIMIT 1
    `;
    if (!villageRows.length) return res.status(404).json({ error: "Village introuvable." });

    if (enabled) {
      await sql`
        INSERT INTO public.tester_access (user_id, village_slug, formula, assigned_by)
        VALUES (${userId}, ${village}, ${formula}, ${req.user.email})
        ON CONFLICT (user_id, village_slug, formula) DO NOTHING
      `;
    } else {
      await sql`
        DELETE FROM public.tester_access
        WHERE user_id = ${userId}
          AND village_slug = ${village}
          AND formula = ${formula}
      `;
    }
    const rows = await sql`
      SELECT id, user_id, village_slug, formula, assigned_at, assigned_by
      FROM public.tester_access
      WHERE user_id = ${userId}
      ORDER BY village_slug ASC, formula ASC
    `;
    res.json({ access: rows });
  } catch (error) {
    console.error("Admin update tester access failed:", error.message);
    res.status(500).json({ error: "Impossible de modifier les accès du testeur." });
  }
});

// Tous les retours sont visibles uniquement par l'administration.
app.get("/api/admin/tester-feedback", requireUser, requireAdmin, async (req, res) => {
  const status = String(req.query?.status || "").trim();
  if (status && !TESTER_FEEDBACK_STATUSES.has(status)) {
    return res.status(400).json({ error: "Filtre de statut invalide." });
  }
  try {
    const rows = await sql`
      SELECT f.id, f.user_id, u.name AS tester_name, u.email AS tester_email,
             f.village_slug, v.name AS village_name, f.formula,
             f.category, f.message, f.status, f.admin_response, f.responded_at, f.created_at, f.updated_at
      FROM public.tester_feedback f
      LEFT JOIN neon_auth."user" u ON u.id::text = f.user_id::text
      LEFT JOIN public.villages v ON v.slug = f.village_slug
      WHERE (${status} = '' OR f.status = ${status})
      ORDER BY f.created_at DESC
      LIMIT 500
    `;
    res.json({ feedback: rows, count: rows.length });
  } catch (error) {
    console.error("Admin tester feedback list failed:", error.message);
    res.status(500).json({ error: "Impossible de charger les retours des testeurs." });
  }
});

app.patch("/api/admin/tester-feedback/:id", requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const status = String(req.body?.status || "");
  const adminResponse = String(req.body?.admin_response || "").trim();
  if (!Number.isSafeInteger(id) || id < 1 || !TESTER_FEEDBACK_STATUSES.has(status) || adminResponse.length > 3000) {
    return res.status(400).json({ error: "Identifiant, statut ou réponse invalide." });
  }
  try {
    const rows = await sql`
      UPDATE public.tester_feedback
      SET status = ${status},
          admin_response = ${adminResponse || null},
          responded_at = CASE WHEN ${adminResponse} <> '' THEN NOW() ELSE responded_at END,
          updated_at = NOW()
      WHERE id = ${id}
      RETURNING id, status, admin_response, responded_at, updated_at
    `;
    if (!rows.length) return res.status(404).json({ error: "Retour introuvable." });
    res.json({ feedback: rows[0] });
  } catch (error) {
    console.error("Admin update tester feedback failed:", error.message);
    res.status(500).json({ error: "Impossible d'enregistrer le suivi du retour." });
  }
});


/* ===== PROFILS EXPLORATEURS ET CLASSEMENT ===== */

/* ===== LISTE DES JOUEURS POUR L'ADMINISTRATION ===== */

/* ===== LISTE DES VRAIS COMPTES NEON POUR L'ADMINISTRATION ===== */

// Récompenses manuelles attribuées par l'administration.
async function ensureExplorerRewardsTable(){
  await sql`CREATE TABLE IF NOT EXISTS public.explorer_rewards (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    reward_type TEXT NOT NULL CHECK (reward_type IN ('badge','village','trophy','access')),
    title TEXT NOT NULL,
    icon TEXT NOT NULL DEFAULT '🎁',
    message TEXT,
    village_slug TEXT,
    formula TEXT,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`;
  await sql`CREATE INDEX IF NOT EXISTS explorer_rewards_user_created_idx ON public.explorer_rewards (user_id, created_at DESC)`;
}

app.get("/api/profile/rewards", requireUser, async (req,res)=>{
  try{
    await ensureExplorerRewardsTable();
    const rows=await sql`SELECT id,reward_type,title,icon,message,village_slug,formula,created_at
      FROM public.explorer_rewards WHERE user_id=${req.user.id} ORDER BY created_at DESC LIMIT 100`;
    res.set("Cache-Control","no-store");res.json({rewards:rows});
  }catch(error){console.error("Player rewards read failed:",error.message);res.status(500).json({error:"Impossible de charger tes récompenses."});}
});

app.get("/api/admin/rewards", requireUser, requireAdmin, async (_req,res)=>{
  try{
    await ensureExplorerRewardsTable();
    const [players,villages,rewards]=await Promise.all([
      sql`SELECT u.id AS user_id, u.name, COALESCE(p.pseudo,u.name,'Explorateur') AS pseudo,
          COALESCE(p.leaderboard_opt_in,FALSE) AS leaderboard_opt_in,
          COUNT(DISTINCT c.adventure_id)::int AS completed_adventures
          FROM neon_auth."user" u
          LEFT JOIN public.explorer_profiles p ON p.user_id::text=u.id::text
          LEFT JOIN public.completed_adventures c ON c.user_id::text=u.id::text
          GROUP BY u.id,u.name,p.pseudo,p.leaderboard_opt_in ORDER BY pseudo ASC LIMIT 500`,
      sql`SELECT slug,name FROM public.villages ORDER BY name ASC`,
      sql`SELECT r.id,r.user_id,r.reward_type,r.title,r.icon,r.message,r.village_slug,r.formula,r.created_at,
          COALESCE(p.pseudo,u.name,'Explorateur') AS pseudo,v.name AS village_name
          FROM public.explorer_rewards r
          LEFT JOIN public.explorer_profiles p ON p.user_id::text=r.user_id
          LEFT JOIN neon_auth."user" u ON u.id::text=r.user_id
          LEFT JOIN public.villages v ON v.slug=r.village_slug
          ORDER BY r.created_at DESC LIMIT 100`
    ]);
    res.set("Cache-Control","no-store");res.json({players,villages,rewards});
  }catch(error){console.error("Admin rewards read failed:",error.message);res.status(500).json({error:"Impossible de charger les récompenses. Vérifie les tables joueurs et villages."});}
});

app.post("/api/admin/rewards", requireUser, requireAdmin, async (req,res)=>{
  const userId=String(req.body?.user_id||"").trim();
  const type=String(req.body?.type||"");
  const title=String(req.body?.title||"").trim().slice(0,120);
  const message=String(req.body?.message||"").trim().slice(0,500);
  const village=String(req.body?.village||"").trim().toLowerCase();
  const formula=String(req.body?.formula||"facile").trim().toLowerCase();
  const formulas=new Set(["enfant","facile","famille","moyen","difficile","extreme","nuit"]);
  if(!userId||!['badge','village','trophy','access'].includes(type))return res.status(400).json({error:"Choisis un joueur et un type de récompense valide."});
  if((type==='badge'||type==='trophy')&&title.length<2)return res.status(400).json({error:"Choisis un nom de récompense."});
  if((type==='village'||type==='access')&&(!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(village)||!formulas.has(formula)))return res.status(400).json({error:"Choisis un village et une formule valides."});
  try{
    await ensureExplorerRewardsTable();
    const player=await sql`SELECT id FROM neon_auth."user" WHERE id::text=${userId} LIMIT 1`;
    if(!player.length)return res.status(404).json({error:"Joueur introuvable."});
    let villageName=null;
    if(type==='village'||type==='access'){
      const found=await sql`SELECT name FROM public.villages WHERE slug=${village} LIMIT 1`;
      if(!found.length)return res.status(404).json({error:"Village introuvable."});
      villageName=found[0].name;
      await sql`INSERT INTO public.user_formula_access (user_id,village,formula,source)
        VALUES (${userId},${village},${formula},'admin')
        ON CONFLICT (user_id,village,formula) DO NOTHING`;
    }
    const icon=type==='badge'?'🏅':type==='village'?'📍':type==='trophy'?'🏆':'🔑';
    const finalTitle=(type==='village'?'Village débloqué : ':type==='access'?'Accès spécial : ':'')+(type==='village'||type==='access'?villageName+(formula?' — '+formula:''):title);
    const inserted=await sql`INSERT INTO public.explorer_rewards
      (user_id,reward_type,title,icon,message,village_slug,formula,created_by)
      VALUES (${userId},${type},${finalTitle},${icon},${message||null},${village||null},${(type==='village'||type==='access')?formula:null},${req.user.email})
      RETURNING id,title,icon,created_at`;
    res.status(201).json({reward:inserted[0],message:`Récompense attribuée : ${finalTitle}.`});
  }catch(error){console.error("Admin reward grant failed:",error.message);res.status(500).json({error:"Impossible d'attribuer cette récompense. Vérifie la table user_formula_access."});}
});

app.get("/api/admin/players", requireUser, requireAdmin, async (req, res) => {
  const search = String(req.query?.search || "").trim().slice(0, 80);

  try {
    const rows = await sql`
      SELECT
        u.id AS user_id,
        u.name AS name,
        u.email AS email,
        u."emailVerified" AS email_verified,
        u."createdAt" AS registered_at,
        COALESCE(p.pseudo, u.name, 'Explorateur') AS pseudo,
        COALESCE(p.leaderboard_opt_in, FALSE) AS leaderboard_opt_in,
        COUNT(DISTINCT c.adventure_id)::int AS completed_adventures,
        COUNT(DISTINCT f.formula)::int AS active_formulas
      FROM neon_auth."user" u
      LEFT JOIN public.explorer_profiles p
        ON p.user_id::text = u.id::text
      LEFT JOIN public.completed_adventures c
        ON c.user_id::text = u.id::text
      LEFT JOIN public.user_formula_access f
        ON f.user_id::text = u.id::text
        AND f.village = 'humbert'
      WHERE (
        ${search} = ''
        OR u.name ILIKE ${'%' + search + '%'}
        OR u.email ILIKE ${'%' + search + '%'}
        OR u.id::text ILIKE ${'%' + search + '%'}
      )
      GROUP BY
        u.id, u.name, u.email, u."emailVerified",
        u."createdAt", p.pseudo, p.leaderboard_opt_in
      ORDER BY u."createdAt" DESC
      LIMIT 500
    `;

    res.json({ players: rows, count: rows.length });

  } catch (error) {
    console.error("Admin Neon players list failed:", error.message);
    res.status(500).json({
      error: "Impossible de charger les comptes Neon."
    });
  }
});
// Crée ou actualise le profil à partir du prénom vérifié par Neon Auth.
app.get("/api/profile", requireUser, async (req, res) => {
  try {
    const pseudo = String(req.user.name || "Explorateur").trim().slice(0, 80) || "Explorateur";
    const rows = await sql`
      INSERT INTO public.explorer_profiles (user_id, pseudo)
      VALUES (${req.user.id}, ${pseudo})
      ON CONFLICT (user_id) DO UPDATE
        SET pseudo = EXCLUDED.pseudo, updated_at = NOW()
      RETURNING pseudo, leaderboard_opt_in
    `;
    res.json({ profile: rows[0] });
  } catch (error) {
    console.error("Read explorer profile failed:", error.message);
    res.status(500).json({ error: "Impossible de charger ton profil." });
  }
});

// Le joueur choisit lui-même s'il souhaite apparaître dans le classement.
app.patch("/api/profile/leaderboard", requireUser, async (req, res) => {
  if (typeof req.body?.leaderboard_opt_in !== "boolean") {
    return res.status(400).json({ error: "Choix de participation invalide." });
  }
  try {
    const pseudo = String(req.user.name || "Explorateur").trim().slice(0, 80) || "Explorateur";
    const rows = await sql`
      INSERT INTO public.explorer_profiles (user_id, pseudo, leaderboard_opt_in)
      VALUES (${req.user.id}, ${pseudo}, ${req.body.leaderboard_opt_in})
      ON CONFLICT (user_id) DO UPDATE
        SET pseudo = EXCLUDED.pseudo,
            leaderboard_opt_in = EXCLUDED.leaderboard_opt_in,
            updated_at = NOW()
      RETURNING pseudo, leaderboard_opt_in
    `;
    res.json({ profile: rows[0] });
  } catch (error) {
    console.error("Update explorer profile failed:", error.message);
    res.status(500).json({ error: "Impossible d'enregistrer ton choix." });
  }
});

// Classement public : aucun e-mail ni identifiant personnel n'est renvoyé.
app.get("/api/leaderboard", async (_req, res) => {
  try {
    // Les identifiants des profils et des aventures peuvent être de types SQL différents.
    // On les compare explicitement en texte, comme dans les requêtes de l'administration.
    const rows = await sql`
      SELECT
        p.pseudo,
        COUNT(DISTINCT c.adventure_id)::int AS villages_count
      FROM public.explorer_profiles p
      LEFT JOIN public.completed_adventures c
        ON c.user_id::text = p.user_id::text
      WHERE p.leaderboard_opt_in = TRUE
      GROUP BY p.user_id, p.pseudo
      ORDER BY villages_count DESC, p.pseudo ASC
      LIMIT 100
    `;
    res.set("Cache-Control", "no-store");
    res.json({ leaderboard: rows });
  } catch (error) {
    console.error("Read leaderboard failed:", error);
    res.status(500).json({ error: "Impossible de charger le classement." });
  }
});

// Alias pour les pages qui utilisent l'ancienne adresse publique.
app.get("/api/public/rewards", async (_req, res) => {
  try {
    const rows = await sql`
      SELECT
        p.pseudo,
        COUNT(DISTINCT c.adventure_id)::int AS villages_count
      FROM public.explorer_profiles p
      LEFT JOIN public.completed_adventures c
        ON c.user_id::text = p.user_id::text
      WHERE p.leaderboard_opt_in = TRUE
      GROUP BY p.user_id, p.pseudo
      ORDER BY villages_count DESC, p.pseudo ASC
      LIMIT 100
    `;
    res.set("Cache-Control", "no-store");
    res.json({ leaderboard: rows, rewards: [] });
  } catch (error) {
    console.error("Read public rewards failed:", error);
    res.status(500).json({ error: "Impossible de charger le classement." });
  }
});

// Enregistre une aventure publiée une seule fois par joueur.
app.post("/api/adventures/:id/complete", requireUser, async (req, res) => {
  const adventureId = Number(req.params.id);
  if (!Number.isSafeInteger(adventureId) || adventureId < 1) {
    return res.status(400).json({ error: "Identifiant d'aventure invalide." });
  }
  try {
    const adventure = await sql`
      SELECT id FROM public.adventures
      WHERE id = ${adventureId} AND is_published = TRUE
    `;
    if (!adventure.length) {
      return res.status(404).json({ error: "Aventure publiée introuvable." });
    }
    const rows = await sql`
      INSERT INTO public.completed_adventures (user_id, adventure_id)
      VALUES (${req.user.id}, ${adventureId})
      ON CONFLICT (user_id, adventure_id) DO NOTHING
      RETURNING user_id, adventure_id, completed_at
    `;
    res.status(200).json({ completed: true, already_completed: rows.length === 0 });
  } catch (error) {
    console.error("Complete adventure failed:", error.message);
    res.status(500).json({ error: "Impossible d'enregistrer cette découverte." });
  }
});

// Validation GPS d'une étape : la position est vérifiée côté serveur.
app.post("/api/adventures/:id/steps/:stepId/validate-gps", requireUser, async (req, res) => {
  const adventureId = Number(req.params.id);
  const stepId = Number(req.params.stepId);
  const latitude = Number(req.body?.latitude);
  const longitude = Number(req.body?.longitude);
  const accuracy = Number(req.body?.accuracy);
  const MAX_DISTANCE_METERS = 100;
  const MAX_ACCURACY_METERS = 50;

  if (!Number.isSafeInteger(adventureId) || adventureId < 1 || !Number.isSafeInteger(stepId) || stepId < 1) {
    return res.status(400).json({ error: "Étape ou aventure invalide." });
  }
  if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90 ||
      !Number.isFinite(longitude) || longitude < -180 || longitude > 180) {
    return res.status(400).json({ error: "Position GPS invalide." });
  }
  if (!Number.isFinite(accuracy) || accuracy <= 0 || accuracy > MAX_ACCURACY_METERS) {
    return res.status(400).json({ error: "La précision GPS est insuffisante. Attends quelques instants et réessaie." });
  }

  try {
    const rows = await sql`
      SELECT s.id, s.adventure_id, s.step_number, s.latitude, s.longitude,
             a.village_slug, a.level_key, a.is_published
      FROM public.adventure_steps s
      JOIN public.adventures a ON a.id = s.adventure_id
      WHERE s.id = ${stepId} AND s.adventure_id = ${adventureId}
      LIMIT 1
    `;
    if (!rows.length) return res.status(404).json({ error: "Étape introuvable." });
    const target = rows[0];
    if (!target.is_published && !(await hasAcceptedTesterAccess(req.user.id, target.village_slug, target.level_key))) {
      return res.status(404).json({ error: "Cette étape est réservée aux testeurs autorisés." });
    }
    if (target.is_published && !(await playerCanAccessAdventure(req.user.id, target))) {
      return res.status(403).json({ error: "Tu n’as pas accès à cette aventure." });
    }
    if (target.latitude == null || target.longitude == null) {
      return res.status(409).json({ error: "Le GPS n'est pas configuré pour cette étape." });
    }

    const distanceRows = await sql`
      SELECT 6371000 * 2 * ASIN(SQRT(
        POWER(SIN(RADIANS(${latitude} - ${Number(target.latitude)}) / 2), 2) +
        COS(RADIANS(${Number(target.latitude)})) * COS(RADIANS(${latitude})) *
        POWER(SIN(RADIANS(${longitude} - ${Number(target.longitude)}) / 2), 2)
      )) AS distance_meters
    `;
    const distance = Number(distanceRows[0].distance_meters);
    if (distance > MAX_DISTANCE_METERS) {
      return res.status(403).json({
        validated: false,
        error: "Tu n'es pas encore assez proche du lieu.",
        distance_meters: Math.round(distance),
        required_distance_meters: MAX_DISTANCE_METERS
      });
    }

    const saved = await sql`
      INSERT INTO public.user_step_validations (user_id, adventure_id, step_id, gps_accuracy_meters, distance_meters)
      VALUES (${req.user.id}, ${adventureId}, ${stepId}, ${accuracy}, ${distance})
      ON CONFLICT (user_id, step_id) DO NOTHING
      RETURNING id, validated_at
    `;
    res.json({
      validated: true,
      already_validated: saved.length === 0,
      step_number: target.step_number,
      distance_meters: Math.round(distance),
      validated_at: saved[0]?.validated_at ?? null
    });
  } catch (error) {
    console.error("GPS step validation failed:", error.message);
    res.status(500).json({ error: "Impossible de valider cette étape pour le moment." });
  }
});

// A player submits a support question.
app.post("/api/support", requireUser, async (req, res) => {
  const subject = String(req.body?.subject ?? "").trim();
  const message = String(req.body?.message ?? "").trim();

  if (subject.length < 3 || subject.length > 120) {
    return res.status(400).json({ error: "Le sujet doit contenir entre 3 et 120 caractères." });
  }
  if (message.length < 5 || message.length > 5000) {
    return res.status(400).json({ error: "Le message doit contenir entre 5 et 5 000 caractères." });
  }

  try {
    const rows = await sql`
      INSERT INTO public.support_requests (user_id, subject, message)
      VALUES (${req.user.id}, ${subject}, ${message})
      RETURNING id, subject, message, status, created_at, updated_at
    `;
    res.status(201).json({ request: rows[0] });
  } catch (error) {
    console.error("Create support request failed:", error.message);
    res.status(500).json({ error: "Impossible d’enregistrer la demande pour le moment." });
  }
});

// A player sees only their own questions and replies.
app.get("/api/support/mine", requireUser, async (req, res) => {
  try {
    const rows = await sql`
      SELECT r.id, r.subject, r.message, r.status, r.created_at, r.updated_at,
        COALESCE(
          json_agg(
            json_build_object(
              'id', p.id,
              'author_user_id', p.author_user_id,
              'message', p.message,
              'created_at', p.created_at
            ) ORDER BY p.created_at
          ) FILTER (WHERE p.id IS NOT NULL),
          '[]'::json
        ) AS replies
      FROM public.support_requests r
      LEFT JOIN public.support_replies p ON p.request_id = r.id
      WHERE r.user_id = ${req.user.id}
      GROUP BY r.id
      ORDER BY r.created_at DESC
      LIMIT 100
    `;
    res.json({ requests: rows });
  } catch (error) {
    console.error("Read own support requests failed:", error.message);
    res.status(500).json({ error: "Impossible de charger l’historique." });
  }
});

// Administrators can list requests.
app.get("/api/admin/support", requireUser, requireStaff, requirePermission("support"), async (req, res) => {
  try {
    const rows = await sql`
      SELECT r.id, r.user_id, r.subject, r.message, r.status, r.created_at, r.updated_at,
        COALESCE(
          json_agg(
            json_build_object(
              'id', p.id,
              'author_user_id', p.author_user_id,
              'message', p.message,
              'created_at', p.created_at
            ) ORDER BY p.created_at
          ) FILTER (WHERE p.id IS NOT NULL),
          '[]'::json
        ) AS replies
      FROM public.support_requests r
      LEFT JOIN public.support_replies p ON p.request_id = r.id
      GROUP BY r.id
      ORDER BY r.created_at DESC
      LIMIT 200
    `;
    res.json({ requests: rows });
  } catch (error) {
    console.error("Admin support list failed:", error.message);
    res.status(500).json({ error: "Impossible de charger les demandes." });
  }
});

// Administrators answer a player and update the request status.
app.post("/api/admin/support/:id/replies", requireUser, requireStaff, requirePermission("support"), async (req, res) => {
  const id = Number(req.params.id);
  const message = String(req.body?.message ?? "").trim();

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: "Identifiant de demande invalide." });
  }
  if (message.length < 2 || message.length > 5000) {
    return res.status(400).json({ error: "La réponse doit contenir entre 2 et 5 000 caractères." });
  }

  try {
    const inserted = await sql`
      INSERT INTO public.support_replies (request_id, author_user_id, message)
      SELECT r.id, ${req.user.id}, ${message}
      FROM public.support_requests r
      WHERE r.id = ${id}
      RETURNING id, request_id, author_user_id, message, created_at
    `;
    if (!inserted.length) return res.status(404).json({ error: "Demande introuvable." });

    await sql`
      UPDATE public.support_requests
      SET status = 'repondu', updated_at = NOW()
      WHERE id = ${id}
    `;
    res.status(201).json({ reply: inserted[0] });
  } catch (error) {
    console.error("Reply to support request failed:", error.message);
    res.status(500).json({ error: "Impossible d’enregistrer la réponse." });
  }
});

app.patch("/api/admin/support/:id/status", requireUser, requireStaff, requirePermission("support"), async (req, res) => {
  const id = Number(req.params.id);
  const status = String(req.body?.status ?? "");
  const allowed = new Set(["en_attente", "en_cours", "repondu", "ferme"]);

  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Identifiant invalide." });
  if (!allowed.has(status)) return res.status(400).json({ error: "Statut invalide." });

  try {
    const rows = await sql`
      UPDATE public.support_requests
      SET status = ${status}, updated_at = NOW()
      WHERE id = ${id}
      RETURNING id, status, updated_at
    `;
    if (!rows.length) return res.status(404).json({ error: "Demande introuvable." });
    res.json({ request: rows[0] });
  } catch (error) {
    console.error("Update support status failed:", error.message);
    res.status(500).json({ error: "Impossible de modifier le statut." });
  }
});


/* ===== CATALOGUE DES NIVEAUX PAR VILLAGE ===== */
const LEVEL_KEYS = new Set(["enfant", "facile", "famille", "moyen", "difficile", "extreme", "nuit"]);
const LEVEL_ACCESS_TYPES = new Set(["gratuit", "payant", "testeur"]);
const LEVEL_STATUSES = new Set(["preparation", "actif", "desactive"]);

app.get("/api/admin/village-levels", requireUser, requireAdmin, async (req, res) => {
  const village = String(req.query?.village || "").trim().toLowerCase();
  if (!village) return res.status(400).json({ error: "Choisis un village." });
  try {
    const rows = await sql`
      SELECT id, village_slug, level_key, display_name, riddle_count, star_count,
             access_type, status, updated_at
      FROM public.village_level_settings
      WHERE village_slug = ${village}
      ORDER BY CASE level_key WHEN 'enfant' THEN 1 WHEN 'facile' THEN 2 WHEN 'famille' THEN 3
        WHEN 'moyen' THEN 4 WHEN 'difficile' THEN 5 WHEN 'extreme' THEN 6 ELSE 7 END
    `;
    res.json({ levels: rows });
  } catch (error) {
    console.error("Read village levels failed:", error.message);
    res.status(500).json({ error: "Impossible de charger les niveaux. Vérifie la table village_level_settings dans Neon." });
  }
});

app.put("/api/admin/village-levels", requireUser, requireAdmin, async (req, res) => {
  const village = String(req.body?.village_slug || "").trim().toLowerCase();
  const level = String(req.body?.level_key || "").trim().toLowerCase();
  const name = String(req.body?.display_name || "").trim();
  const riddles = Number(req.body?.riddle_count);
  const stars = Number(req.body?.star_count);
  const access = String(req.body?.access_type || "gratuit");
  const status = String(req.body?.status || "preparation");
  if (!village || !LEVEL_KEYS.has(level) || name.length < 2 || name.length > 60 ||
      !Number.isSafeInteger(riddles) || riddles < 1 || riddles > 200 ||
      !Number.isSafeInteger(stars) || stars < 0 || stars > 1000 ||
      !LEVEL_ACCESS_TYPES.has(access) || !LEVEL_STATUSES.has(status)) {
    return res.status(400).json({ error: "Paramètres du niveau invalides." });
  }
  try {
    const villageRows = await sql`SELECT slug FROM public.villages WHERE slug = ${village} LIMIT 1`;
    if (!villageRows.length) return res.status(404).json({ error: "Village introuvable." });
    const rows = await sql`
      INSERT INTO public.village_level_settings
        (village_slug, level_key, display_name, riddle_count, star_count, access_type, status, updated_at)
      VALUES (${village}, ${level}, ${name}, ${riddles}, ${stars}, ${access}, ${status}, NOW())
      ON CONFLICT (village_slug, level_key) DO UPDATE SET
        display_name = EXCLUDED.display_name, riddle_count = EXCLUDED.riddle_count,
        star_count = EXCLUDED.star_count, access_type = EXCLUDED.access_type,
        status = EXCLUDED.status, updated_at = NOW()
      RETURNING id, village_slug, level_key, display_name, riddle_count, star_count,
                access_type, status, updated_at
    `;
    res.json({ level: rows[0] });
  } catch (error) {
    console.error("Save village level failed:", error.message);
    res.status(500).json({ error: "Impossible d'enregistrer ce niveau." });
  }
});

/* ===== ADMINISTRATION DES AVENTURES ===== */

// Lister les aventures
app.get("/api/admin/adventures", requireUser, requireAdmin, async (_req, res) => {
  try {
    const rows = await sql`
      SELECT id, title, village, village_slug, level_key, description, status, is_validated, is_published, created_at, updated_at
      FROM public.adventures
      ORDER BY id DESC
    `;
    res.json({ adventures: rows });
  } catch (error) {
    console.error("Admin adventures list failed:", error.message);
    res.status(500).json({ error: "Impossible de charger les aventures." });
  }
});

// Créer une aventure
app.post("/api/admin/adventures", requireUser, requireAdmin, async (req, res) => {
  const title = String(req.body?.title ?? "").trim();
  const village = String(req.body?.village ?? "").trim();
  const description = String(req.body?.description ?? "").trim();
  const villageSlug = String(req.body?.village_slug ?? "").trim().toLowerCase();
  const levelKey = String(req.body?.level_key ?? "").trim().toLowerCase();

  if (title.length < 2 || title.length > 150) {
    return res.status(400).json({ error: "Le titre doit contenir entre 2 et 150 caractères." });
  }
  if (village.length < 2 || village.length > 150) {
    return res.status(400).json({ error: "Le village doit contenir entre 2 et 150 caractères." });
  }

  if (!villageSlug || !LEVEL_KEYS.has(levelKey)) return res.status(400).json({ error: "Choisis un village et un niveau." });

  try {
    const configured = await sql`
      SELECT v.name, l.level_key FROM public.villages v
      JOIN public.village_level_settings l ON l.village_slug = v.slug
      WHERE v.slug = ${villageSlug} AND l.level_key = ${levelKey}
      LIMIT 1
    `;
    if (!configured.length) return res.status(400).json({ error: "Ce niveau n'est pas configuré pour ce village." });
    const rows = await sql`
      INSERT INTO public.adventures (title, village, village_slug, level_key, description)
      VALUES (${title}, ${village}, ${villageSlug}, ${levelKey}, ${description})
      RETURNING id, title, village, village_slug, level_key, description, status, is_validated, is_published, created_at, updated_at
    `;
    res.status(201).json({ adventure: rows[0] });
  } catch (error) {
    console.error("Create adventure failed:", error.message);
    res.status(500).json({ error: "Impossible de créer l’aventure." });
  }
});

// Modifier les informations et le statut d’une aventure. Ne publie jamais automatiquement.
app.patch("/api/admin/adventures/:id", requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const title = String(req.body?.title ?? "").trim();
  const village = String(req.body?.village ?? "").trim();
  const description = String(req.body?.description ?? "").trim();
  const status = String(req.body?.status ?? "en_creation");
  const allowedStatuses = new Set(["en_creation", "a_valider", "en_attente", "en_travaux", "mise_a_jour", "en_ligne", "suspendue"]);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Identifiant d’aventure invalide." });
  if (title.length < 2 || title.length > 150 || village.length < 2 || village.length > 150 || description.length > 3000 || !allowedStatuses.has(status))
    return res.status(400).json({ error: "Informations ou statut de l’aventure invalides." });
  try {
    const rows = await sql`
      UPDATE public.adventures
      SET title = ${title}, village = ${village}, description = ${description}, status = ${status},
          is_published = CASE WHEN ${status} = 'suspendue' THEN FALSE ELSE is_published END,
          updated_at = NOW()
      WHERE id = ${id}
      RETURNING id, title, village, village_slug, level_key, description, status, is_validated, is_published, created_at, updated_at
    `;
    if (!rows.length) return res.status(404).json({ error: "Aventure introuvable." });
    res.json({ adventure: rows[0] });
  } catch (error) {
    console.error("Update adventure failed:", error.message);
    res.status(500).json({ error: "Impossible de modifier l’aventure." });
  }
});

// Valider le contenu sans le publier.
app.post("/api/admin/adventures/:id/validate", requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Identifiant d’aventure invalide." });
  try {
    const rows = await sql`
      UPDATE public.adventures SET is_validated = TRUE, status = CASE WHEN status = 'en_creation' THEN 'a_valider' ELSE status END, updated_at = NOW()
      WHERE id = ${id}
      RETURNING id, title, status, is_validated, is_published
    `;
    if (!rows.length) return res.status(404).json({ error: "Aventure introuvable." });
    res.json({ adventure: rows[0], message: "Aventure validée. Elle n’est pas publiée." });
  } catch (error) {
    console.error("Validate adventure failed:", error.message);
    res.status(500).json({ error: "Impossible de valider l’aventure." });
  }
});

// La publication est une action séparée et exige une validation préalable.
app.post("/api/admin/adventures/:id/publish", requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Identifiant d’aventure invalide." });
  try {
    const rows = await sql`
      UPDATE public.adventures SET is_published = TRUE, status = 'en_ligne', updated_at = NOW()
      WHERE id = ${id} AND is_validated = TRUE AND status <> 'suspendue'
      RETURNING id, title, status, is_validated, is_published
    `;
    if (!rows.length) {
      const existing = await sql`SELECT id, is_validated, status FROM public.adventures WHERE id = ${id} LIMIT 1`;
      if (!existing.length) return res.status(404).json({ error: "Aventure introuvable." });
      return res.status(409).json({ error: existing[0].status === "suspendue" ? "Cette aventure est suspendue. Réactive son statut avant publication." : "Valide d’abord l’aventure avant de la mettre en ligne." });
    }
    res.json({ adventure: rows[0], message: "Aventure mise en ligne." });
  } catch (error) {
    console.error("Publish adventure failed:", error.message);
    res.status(500).json({ error: "Impossible de publier l’aventure." });
  }
});

// Consulter les étapes d’une aventure
app.get("/api/admin/adventures/:id/steps", requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: "Identifiant d’aventure invalide." });
  }

  try {
    const adventures = await sql`
      SELECT a.id, a.level_key, a.village_slug, l.riddle_count, l.star_count, l.display_name
      FROM public.adventures a
      LEFT JOIN public.village_level_settings l
        ON l.village_slug = a.village_slug AND l.level_key = a.level_key
      WHERE a.id = ${id}
    `;
    if (!adventures.length) {
      return res.status(404).json({ error: "Aventure introuvable." });
    }

    const steps = await sql`
      SELECT id, adventure_id, step_number, place_name,
             latitude, longitude, photo_url, riddle, answer, hint
      FROM public.adventure_steps
      WHERE adventure_id = ${id}
      ORDER BY step_number ASC
    `;
    res.json({ steps, level: adventures[0] });
  } catch (error) {
    console.error("Read adventure steps failed:", error.message);
    res.status(500).json({ error: "Impossible de charger les étapes." });
  }
});

 
// Ajouter une étape à une aventure
app.post("/api/admin/adventures/:id/steps", requireUser, requireAdmin, async (req, res) => {
  const adventureId = Number(req.params.id);
  const stepNumber = Number(req.body?.step_number);
  const placeName = String(req.body?.place_name ?? "").trim();
  const riddle = String(req.body?.riddle ?? "").trim();
  const answer = String(req.body?.answer ?? "").trim();
  const hint = String(req.body?.hint ?? "").trim();
  const photoUrl = String(req.body?.photo_url ?? "").trim();
  const latitude = req.body?.latitude == null || req.body.latitude === ""
    ? null : Number(req.body.latitude);
  const longitude = req.body?.longitude == null || req.body.longitude === ""
    ? null : Number(req.body.longitude);

  if (!Number.isSafeInteger(adventureId) || adventureId < 1) {
    return res.status(400).json({ error: "Identifiant d’aventure invalide." });
  }
  if (!Number.isSafeInteger(stepNumber) || stepNumber < 1) {
    return res.status(400).json({ error: "Le numéro d’étape doit être un entier positif." });
  }
  if (!placeName || placeName.length > 200) {
    return res.status(400).json({ error: "Le lieu est obligatoire et limité à 200 caractères." });
  }
  if (photoUrl.length > 2000 || (photoUrl && !/^https:\/\//i.test(photoUrl))) {
    return res.status(400).json({ error: "La photo doit être une adresse HTTPS valide." });
  }
  if (latitude !== null && (!Number.isFinite(latitude) || latitude < -90 || latitude > 90)) {
    return res.status(400).json({ error: "Latitude invalide." });
  }
  if (longitude !== null && (!Number.isFinite(longitude) || longitude < -180 || longitude > 180)) {
    return res.status(400).json({ error: "Longitude invalide." });
  }

  try {
    const levelInfo = await sql`
      SELECT l.riddle_count FROM public.adventures a
      LEFT JOIN public.village_level_settings l ON l.village_slug = a.village_slug AND l.level_key = a.level_key
      WHERE a.id = ${adventureId}
    `;
    if (!levelInfo.length) return res.status(404).json({ error: "Aventure introuvable." });
    if (levelInfo[0].riddle_count != null && stepNumber > Number(levelInfo[0].riddle_count)) {
      return res.status(400).json({ error: `Ce niveau est prévu pour ${levelInfo[0].riddle_count} étapes maximum.` });
    }
    const rows = await sql`
      INSERT INTO public.adventure_steps
        (adventure_id, step_number, place_name, latitude, longitude, photo_url, riddle, answer, hint)
      SELECT id, ${stepNumber}, ${placeName}, ${latitude}, ${longitude}, ${photoUrl || null}, ${riddle}, ${answer}, ${hint}
      FROM public.adventures
      WHERE id = ${adventureId}
      RETURNING id, adventure_id, step_number, place_name,
                latitude, longitude, photo_url, riddle, answer, hint
    `;

    if (!rows.length) {
      return res.status(404).json({ error: "Aventure introuvable." });
    }

    res.status(201).json({ step: rows[0] });
  } catch (error) {
    console.error("Create adventure step failed:", error.message);
    if (error.code === "23505") {
      return res.status(409).json({ error: "Ce numéro d’étape existe déjà pour cette aventure." });
    }
    res.status(500).json({ error: "Impossible d’enregistrer l’étape." });
  }
});

/* ===== SUPPRIMER UNE AVENTURE ===== */
app.delete("/api/admin/adventures/:id", requireUser, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: "Identifiant d’aventure invalide." });
  }

  try {
    const rows = await sql`
      DELETE FROM public.adventures
      WHERE id = ${id}
      RETURNING id, title
    `;

    if (!rows.length) {
      return res.status(404).json({ error: "Aventure introuvable." });
    }

    res.json({
      ok: true,
      message: "Aventure supprimée.",
      adventure: rows[0]
    });
  } catch (error) {
    console.error("Delete adventure failed:", error.message);
    res.status(500).json({ error: "Impossible de supprimer l’aventure." });
  }
});


/* ===== ACCES JOUEUR AUX AVENTURES PUBLIEES ===== */
async function playerCanAccessAdventure(userId, adventure) {
  const village = String(adventure.village_slug || '').toLowerCase();
  const level = String(adventure.level_key || '').toLowerCase();
  if (!village || !level) return false;
  const tester = await sql`
    SELECT 1 FROM public.tester_applications t
    JOIN public.tester_access a ON a.user_id = t.user_id
    WHERE t.user_id = ${userId} AND t.status = 'accepted'
      AND a.village_slug = ${village} AND a.formula = ${level}
    LIMIT 1
  `;
  if (tester.length) return true;
  const paid = await sql`
    SELECT 1 FROM public.user_formula_access
    WHERE user_id = ${userId} AND village = ${village} AND formula = ${level}
    LIMIT 1
  `;
  return paid.length > 0;
}

// Liste uniquement les aventures publiées auxquelles le joueur a réellement accès.
app.get('/api/adventures', requireUser, async (req, res) => {
  try {
    const rows = await sql`
      SELECT a.id, a.title, a.description, a.village_slug, a.level_key,
             COALESCE(l.display_name, a.level_key) AS level_name,
             COALESCE(l.riddle_count, 0)::int AS total_steps,
             COALESCE(l.star_count, 0)::int AS total_stars
      FROM public.adventures a
      LEFT JOIN public.village_level_settings l
        ON l.village_slug = a.village_slug AND l.level_key = a.level_key
      WHERE a.is_published = TRUE AND a.village_slug IS NOT NULL AND a.level_key IS NOT NULL
      ORDER BY a.village_slug, a.level_key, a.title
    `;
    const accessible = [];
    for (const adventure of rows) {
      if (await playerCanAccessAdventure(req.user.id, adventure)) accessible.push(adventure);
    }
    res.json({ adventures: accessible });
  } catch (error) {
    console.error('List player adventures failed:', error.message);
    res.status(500).json({ error: 'Impossible de charger tes aventures.' });
  }
});

// Les coordonnées servent au GPS. L'énigme et l'indice ne sont révélés qu'après validation GPS.
// La réponse n'est jamais envoyée au navigateur.
app.get('/api/adventures/:id/steps', requireUser, async (req, res) => {
  const adventureId = Number(req.params.id);
  if (!Number.isSafeInteger(adventureId) || adventureId < 1)
    return res.status(400).json({ error: 'Identifiant d’aventure invalide.' });
  try {
    const adventures = await sql`
      SELECT id, title, village_slug, level_key, is_published FROM public.adventures
      WHERE id = ${adventureId} LIMIT 1
    `;
    if (!adventures.length) return res.status(404).json({ error: 'Aventure introuvable.' });
    const adventure = adventures[0];
    const testerAllowed = !adventure.is_published && await hasAcceptedTesterAccess(req.user.id, adventure.village_slug, adventure.level_key);
    if (!adventure.is_published && !testerAllowed)
      return res.status(404).json({ error: 'Ce parcours est réservé aux testeurs autorisés.' });
    if (adventure.is_published && !(await playerCanAccessAdventure(req.user.id, adventure)))
      return res.status(403).json({ error: 'Tu n’as pas accès à cette aventure.' });
    const rows = await sql`
      SELECT s.id, s.step_number, s.place_name, s.latitude, s.longitude,
             CASE WHEN uv.step_id IS NOT NULL THEN s.riddle ELSE NULL END AS riddle,
             CASE WHEN uv.step_id IS NOT NULL THEN s.hint ELSE NULL END AS hint,
             (uv.step_id IS NOT NULL) AS validated
      FROM public.adventure_steps s
      LEFT JOIN public.user_step_validations uv
        ON uv.step_id = s.id AND uv.adventure_id = s.adventure_id AND uv.user_id = ${req.user.id}
      WHERE s.adventure_id = ${adventureId}
      ORDER BY s.step_number ASC
    `;
    res.json({ adventure: adventures[0], steps: rows });
  } catch (error) {
    console.error('Read player adventure steps failed:', error.message);
    res.status(500).json({ error: 'Impossible de charger les étapes.' });
  }
});

/* ===== PROGRESSION ET ETOILES DU JOUEUR ===== */
// Les étoiles sont calculées à partir des validations GPS enregistrées dans Neon.
// Le navigateur ne peut pas envoyer lui-même un nombre d'étoiles.
app.get("/api/adventures/:id/progress", requireUser, async (req, res) => {
  const adventureId = Number(req.params.id);
  if (!Number.isSafeInteger(adventureId) || adventureId < 1) {
    return res.status(400).json({ error: "Identifiant d’aventure invalide." });
  }

  try {
    const adventures = await sql`
      SELECT a.id, a.title, a.village_slug, a.level_key,
             COALESCE(l.riddle_count, 0)::int AS riddle_count,
             COALESCE(l.star_count, 0)::int AS star_count, a.is_published
      FROM public.adventures a
      LEFT JOIN public.village_level_settings l
        ON l.village_slug = a.village_slug AND l.level_key = a.level_key
      WHERE a.id = ${adventureId}
      LIMIT 1
    `;
    if (!adventures.length) {
      return res.status(404).json({ error: "Aventure introuvable." });
    }
    const adventureAccess = adventures[0];
    const testerAllowed = !adventureAccess.is_published && await hasAcceptedTesterAccess(req.user.id, adventureAccess.village_slug, adventureAccess.level_key);
    if (!adventureAccess.is_published && !testerAllowed) {
      return res.status(404).json({ error: "Ce parcours est réservé aux testeurs autorisés." });
    }
    if (adventureAccess.is_published && !(await playerCanAccessAdventure(req.user.id, adventureAccess))) {
      return res.status(403).json({ error: "Tu n’as pas accès à cette aventure." });
    }

    const validations = await sql`
      SELECT uv.step_id, s.step_number, uv.validated_at
      FROM public.user_step_validations uv
      JOIN public.adventure_steps s
        ON s.id = uv.step_id AND s.adventure_id = uv.adventure_id
      WHERE uv.user_id = ${req.user.id}
        AND uv.adventure_id = ${adventureId}
      ORDER BY s.step_number ASC
    `;

    const adventure = adventures[0];
    const validatedSteps = validations.length;
    const starsEarned = Math.min(validatedSteps, Number(adventure.star_count || 0));
    res.json({
      adventure_id: adventureId,
      village_slug: adventure.village_slug,
      level_key: adventure.level_key,
      validated_steps: validatedSteps,
      total_steps: Number(adventure.riddle_count || 0),
      stars_earned: starsEarned,
      total_stars: Number(adventure.star_count || 0),
      completed: Number(adventure.riddle_count || 0) > 0 &&
        validatedSteps >= Number(adventure.riddle_count),
      validated_step_ids: validations.map((item) => Number(item.step_id)),
      validated_step_numbers: validations.map((item) => Number(item.step_number))
    });
  } catch (error) {
    console.error("Read adventure progress failed:", error.message);
    res.status(500).json({ error: "Impossible de charger ta progression." });
  }
});

app.use((error, _req, res, _next) => {
  console.error(error.message);
  if (error.message === "Origin not allowed by CORS") {
    return res.status(403).json({ error: "Origine non autorisée." });
  }
  res.status(500).json({ error: "Erreur serveur." });
});

// ── DEMANDES DES MAIRIES & PARTENAIRES ──────────────────────────────────────
function partnerMailer(){
  const {SMTP_HOST,SMTP_PORT,SMTP_USER,SMTP_PASS}=process.env;
  if(!SMTP_HOST||!SMTP_PORT||!SMTP_USER||!SMTP_PASS||!process.env.PARTNER_CONTACT_EMAIL)return null;
  return nodemailer.createTransport({host:SMTP_HOST,port:Number(SMTP_PORT),secure:String(process.env.SMTP_SECURE||"false")==="true",auth:{user:SMTP_USER,pass:SMTP_PASS}});
}
const partnerStatuses=new Set(["en_attente","en_cours","repondu","ferme"]);
const allowedPartnerMime=new Set(["application/pdf","image/jpeg","image/png","image/webp","application/msword","application/vnd.openxmlformats-officedocument.wordprocessingml.document"]);
app.post("/api/partner-requests",async(req,res)=>{
  const municipality=String(req.body?.municipality||"").trim(),contactName=String(req.body?.contact_name||"").trim(),contactEmail=String(req.body?.contact_email||"").trim().toLowerCase(),subject=String(req.body?.subject||"").trim(),message=String(req.body?.message||"").trim();
  if(String(req.body?.website||"").trim())return res.status(400).json({error:"Demande invalide."});
  if(municipality.length<2||municipality.length>120||!/^\S+@\S+\.\S+$/.test(contactEmail)||contactEmail.length>180||subject.length<3||subject.length>120||message.length<5||message.length>3000||contactName.length>120)return res.status(400).json({error:"Vérifie les champs obligatoires du formulaire."});
  let attachment=null;
  if(req.body?.attachment){const a=req.body.attachment;const name=String(a.name||"").slice(0,180),type=String(a.type||"application/octet-stream"),data=String(a.data||"");if(!allowedPartnerMime.has(type)||!name||!data||data.length>7_000_000)return res.status(400).json({error:"Pièce jointe non autorisée ou trop volumineuse (5 Mo maximum)."});attachment={name,type,data};}
  try{
    const rows=await sql`INSERT INTO public.partner_requests (municipality,contact_name,contact_email,subject,message,attachment_name,attachment_type,attachment_data,status) VALUES (${municipality},${contactName||null},${contactEmail},${subject},${message},${attachment?.name||null},${attachment?.type||null},${attachment?.data||null},'en_attente') RETURNING id,created_at`;
    let emailSent=false;const transporter=partnerMailer();
    if(transporter){try{await transporter.sendMail({from:process.env.SMTP_FROM||process.env.SMTP_USER,to:process.env.PARTNER_CONTACT_EMAIL,replyTo:contactEmail,subject:`Nouvelle demande partenaire — ${municipality}`,text:`Nouvelle demande reçue sur Trésors de nos Villages\n\nCommune : ${municipality}\nContact : ${contactName||"Non précisé"}\nE-mail : ${contactEmail}\nObjet : ${subject}\n\n${message}\n\nRéférence : ${rows[0].id}`,attachments:attachment?[{filename:attachment.name,content:Buffer.from(attachment.data,"base64"),contentType:attachment.type}]:[]});emailSent=true;}catch(mailError){console.error("Partner notification email failed:",mailError.message);}}
    res.status(201).json({ok:true,id:rows[0].id,email_sent:emailSent});
  }catch(error){console.error("Create partner request failed:",error.message);res.status(500).json({error:"Impossible d’enregistrer la demande pour le moment."});}
});
app.get("/api/admin/partner-requests",requireUser,requireAdmin,async(_req,res)=>{try{const requests=await sql`SELECT id,municipality,contact_name,contact_email,subject,message,attachment_name,status,admin_response,created_at,updated_at FROM public.partner_requests ORDER BY created_at DESC LIMIT 200`;res.json({requests});}catch(error){console.error("List partner requests failed:",error.message);res.status(500).json({error:"Impossible de charger les demandes partenaires."});}});
app.get("/api/admin/partner-requests/:id/attachment",requireUser,requireAdmin,async(req,res)=>{const id=Number(req.params.id);if(!Number.isSafeInteger(id)||id<1)return res.status(400).json({error:"Identifiant invalide."});try{const rows=await sql`SELECT attachment_name,attachment_type,attachment_data FROM public.partner_requests WHERE id=${id}`;if(!rows.length||!rows[0].attachment_data)return res.status(404).json({error:"Pièce jointe introuvable."});const name=String(rows[0].attachment_name||"document").replace(/[\\r\\n"\\\\]/g,"_");res.setHeader("Content-Type",rows[0].attachment_type||"application/octet-stream");res.setHeader("Content-Disposition",`attachment; filename="${name}"`);res.send(Buffer.from(rows[0].attachment_data,"base64"));}catch(error){console.error("Partner attachment download failed:",error.message);res.status(500).json({error:"Impossible de télécharger le document."});}});
app.patch("/api/admin/partner-requests/:id",requireUser,requireAdmin,async(req,res)=>{const id=Number(req.params.id),status=String(req.body?.status||"");if(!Number.isSafeInteger(id)||id<1)return res.status(400).json({error:"Identifiant invalide."});if(!partnerStatuses.has(status))return res.status(400).json({error:"Statut invalide."});try{const rows=await sql`UPDATE public.partner_requests SET status=${status},updated_at=NOW() WHERE id=${id} RETURNING id,status,updated_at`;if(!rows.length)return res.status(404).json({error:"Demande introuvable."});res.json({request:rows[0]});}catch(error){console.error("Partner request status update failed:",error.message);res.status(500).json({error:"Impossible de modifier le statut."});}});
app.post("/api/admin/partner-requests/:id/reply",requireUser,requireAdmin,async(req,res)=>{const id=Number(req.params.id),message=String(req.body?.message||"").trim();if(!Number.isSafeInteger(id)||id<1)return res.status(400).json({error:"Identifiant invalide."});if(message.length<2||message.length>5000)return res.status(400).json({error:"La réponse doit contenir entre 2 et 5 000 caractères."});try{const rows=await sql`SELECT municipality,contact_email,subject FROM public.partner_requests WHERE id=${id}`;if(!rows.length)return res.status(404).json({error:"Demande introuvable."});const transporter=partnerMailer();if(!transporter)return res.status(503).json({error:"L’envoi e-mail n’est pas configuré sur le serveur."});await transporter.sendMail({from:process.env.SMTP_FROM||process.env.SMTP_USER,to:rows[0].contact_email,replyTo:process.env.PARTNER_CONTACT_EMAIL,subject:`Réponse à votre demande — ${rows[0].municipality}`,text:`Bonjour,\n\nConcernant votre demande « ${rows[0].subject} » :\n\n${message}\n\nBien cordialement,\nTrésors de nos Villages`});await sql`UPDATE public.partner_requests SET admin_response=${message},status='repondu',updated_at=NOW() WHERE id=${id}`;res.json({sent:true});}catch(error){console.error("Partner reply failed:",error.message);res.status(500).json({error:"Impossible d’envoyer la réponse."});}});

const port = Number(process.env.PORT || 10000);
app.listen(port, "0.0.0.0", () => {
  console.log(`Trésors API listening on port ${port}`);
});
