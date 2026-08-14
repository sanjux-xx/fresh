// ============================================
// ProductFilter Service Worker — sw.js
// Place this file in /static/sw.js
// ============================================

// CACHE_NAME, STATIC_ASSETS and the notification icons are injected by the
// /sw.js route in app.py, so the precache list carries the same content-hashed
// URLs the pages request (no second copy of every asset) and the cache name
// changes whenever an asset does (so a deploy cannot leave a stale cache
// pinned). The placeholders below are only ever seen if this file is served
// straight off disk without going through that route.
const CACHE_NAME = '__CACHE_NAME__';

const STATIC_ASSETS = __STATIC_ASSETS__;

const NOTIFY_ICON  = '__NOTIFY_ICON__';
const NOTIFY_BADGE = '__NOTIFY_BADGE__';

// ── Install: cache static assets ──
// This used to call cache.addAll() over a list containing
// /static/images/icon-192.png, /static/images/icon-72.png and
// /static/images/cs-icon.png — none of which exist; the icons live in
// /static/icons/. addAll() rejects atomically if any one request fails, so the
// install failed every time and the service worker never activated: no
// precache, no offline fallback, and no error anywhere a user would see.
// Caching entries individually means a bad entry degrades only itself.
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => Promise.all(
      STATIC_ASSETS.map(url =>
        cache.add(new Request(url, { cache: 'reload' })).catch(err => {
          console.warn('[sw] precache skipped', url, err);
        })
      )
    ))
  );
  self.skipWaiting();
});

// ── Activate: clean old caches ──
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      )
    )
  );
  clients.claim();
});

// ── Fetch: network first, fallback to cache ──
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  if (!event.request.url.startsWith(self.location.origin)) return;

  // Always fetch fresh for API and search requests
  const url = new URL(event.request.url);
  if (url.pathname.startsWith('/api/')) return;

  event.respondWith(
    fetch(event.request)
      .then(response => {
        if (response && response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      })
      .catch(() =>
        caches.match(event.request).then(cached => {
          if (cached) return cached;
          if (event.request.mode === 'navigate') return caches.match('/');
        })
      )
  );
});

// ── Handle push notifications from server ──
self.addEventListener('push', (event) => {
  const data = event.data ? event.data.json() : {};
  const title = data.title || 'ProductFilter Price Alert 🔔';
  const options = {
    body:    data.body || 'A product price has dropped!',
    icon:    NOTIFY_ICON,
    badge:   NOTIFY_BADGE,
    tag:     data.tag || 'price-alert',
    vibrate: [200, 100, 200],
    data:    { url: data.url || '/' },
    actions: [
      { action: 'view',    title: '🛒 View Deal' },
      { action: 'dismiss', title: '✕ Dismiss'   },
    ]
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

// ── Handle notification click ──
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  if (event.action === 'dismiss') return;

  const url = event.notification.data?.url || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url === url && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});

// ── Background price check (triggered by main thread) ──
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'CHECK_PRICES') {
    checkPriceAlerts(event.data.alerts);
  }
});

async function checkPriceAlerts(alerts) {
  if (!alerts || alerts.length === 0) return;

  for (const alert of alerts) {
    try {
      const res = await fetch(`/api/price-check?title=${encodeURIComponent(alert.title)}`);
      if (!res.ok) continue;
      const data = await res.json();

      if (data.current_price && data.current_price <= alert.target_price) {
        await self.registration.showNotification('💰 Price Drop Alert — ProductFilter', {
          body:    `${alert.title} is now ₹${data.current_price} (your target: ₹${alert.target_price})`,
          icon:    NOTIFY_ICON,
          badge:   NOTIFY_BADGE,
          tag:     `alert-${alert.id}`,
          vibrate: [200, 100, 200],
          data:    { url: data.link || '/' },
          actions: [
            { action: 'view',    title: '🛒 Buy Now' },
            { action: 'dismiss', title: '✕ Dismiss'  },
          ]
        });
      }
    } catch (err) {
      console.error('Price check failed:', err);
    }
  }
}