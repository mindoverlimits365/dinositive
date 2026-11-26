const C = 'pv-v7';
const A = ['./', './index.html', './manifest.json', './icon-192.png', './icon-512.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(C).then((c) => c.addAll(A)).catch(() => {}).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== C).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Network-first untuk halaman HTML/navigasi agar build baru tidak pernah tertimpa cache lama
  if (req.mode === 'navigate' || url.pathname.endsWith('/') || url.pathname.endsWith('.html')) {
    e.respondWith(
      fetch(req)
        .then((res) => {
          if (res.ok && res.type === 'basic') {
            const cp = res.clone();
            caches.open(C).then((c) => c.put(req, cp)).catch(() => {});
          }
          return res;
        })
        .catch(() => caches.match(req).then((r) => r || caches.match('./index.html')))
    );
    return;
  }

  e.respondWith(
    caches.match(req).then((cached) => cached || fetch(req).then((res) => {
      if (res.ok && res.type === 'basic') {
        const cp = res.clone();
        caches.open(C).then((c) => c.put(req, cp)).catch(() => {});
      }
      return res;
    }))
  );
});
