const CACHE_NAME = "tresors-villages-pwa-v1";
const APP_SHELL = ["./", "./index.html", "./manifest.webmanifest", "./icons/icon-192.png", "./icons/icon-512.png", "./icons/icon-512-maskable.png"];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(key => key.startsWith("tresors-villages-pwa-") && key !== CACHE_NAME).map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Ne jamais mettre en cache les API : comptes, progression et données privées
  // doivent continuer à être lus sur le serveur.
  if (url.pathname.includes("/api/")) return;

  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).then(response => {
        if (response && response.ok) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put("./index.html", copy));
        }
        return response;
      }).catch(async () => {
        return (await caches.match("./index.html")) || (await caches.match("./")) ||
          new Response("Cette page n'est pas encore disponible hors connexion. Reconnectez-vous pour charger le site.", {
            status: 503, headers: { "Content-Type": "text/plain; charset=utf-8" }
          });
      })
    );
    return;
  }

  // Mise en cache prudente des ressources statiques du même site déjà consultées.
  if (["image", "style", "script", "font"].includes(request.destination)) {
    event.respondWith(
      caches.match(request).then(cached => {
        const network = fetch(request).then(response => {
          if (response && response.ok) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
          }
          return response;
        });
        return cached || network;
      })
    );
  }
});
