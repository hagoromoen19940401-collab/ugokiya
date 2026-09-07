/* 動きやー！ Service Worker
   - アプリシェルのキャッシュ（オフラインでも開ける）
   - 通知の表示 / タップ時のアプリ復帰
   注意: iOS(Safari/ホーム画面PWA)には「指定時刻に自動で起こす」APIが無いため、
        SW単体でアプリを閉じた状態から通知を出すことはできません。
        ここでは「アプリが動いている間の通知表示」と「タップ時の復帰」を担当します。
*/

const CACHE = 'ugokiya-v1';
const ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable-512.png',
  './icons/apple-touch-icon.png'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => Promise.allSettled(ASSETS.map((u) => c.add(u))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// GET / 同一オリジンのみ。HTMLはネット優先、それ以外はキャッシュ優先。
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  const isHTML = req.mode === 'navigate' ||
    (req.headers.get('accept') || '').includes('text/html');

  if (isHTML) {
    e.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
          return res;
        })
        .catch(() => caches.match(req).then((r) => r || caches.match('./index.html')))
    );
    return;
  }

  e.respondWith(
    caches.match(req).then((hit) => hit || fetch(req).then((res) => {
      if (res && res.ok && res.type === 'basic') {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
      }
      return res;
    }).catch(() => hit))
  );
});

function showNag(payload) {
  const data = payload || {};
  return self.registration.showNotification(data.title || '動きやー！🏃', {
    body: data.body || 'まだ運動してへんで？10分だけでも動きやー。',
    icon: './icons/icon-192.png',
    badge: './icons/icon-192.png',
    tag: data.tag || 'ugokiya-daily',
    renotify: true,
    requireInteraction: false,
    data: { url: './index.html' }
  });
}

// ページ側からの依頼で通知を出す
self.addEventListener('message', (e) => {
  const msg = e.data || {};
  if (msg.type === 'SKIP_WAITING') { self.skipWaiting(); return; }
  if (msg.type === 'SHOW_NAG') { e.waitUntil(showNag(msg.payload)); }
});

// Web Push（将来サーバーを用意した場合に動く。iOSもPWA登録済みなら対応）
self.addEventListener('push', (e) => {
  let payload = {};
  try { payload = e.data ? e.data.json() : {}; } catch (err) { payload = {}; }
  e.waitUntil(showNag(payload));
});

// 定期同期（Android Chrome等のみ。iOSでは動かないがエラーにもならない）
self.addEventListener('periodicsync', (e) => {
  if (e.tag === 'ugokiya-daily') e.waitUntil(showNag({}));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of list) {
      if ('focus' in c) return c.focus();
    }
    if (self.clients.openWindow) return self.clients.openWindow('./index.html');
  })());
});
