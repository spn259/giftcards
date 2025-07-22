self.addEventListener('install', event => {
  // Optionally pre-cache assets here
  console.log('SW installed');
});

self.addEventListener('activate', event => {
  console.log('SW activated');
});
self.addEventListener('push', event => {
  let payload = {};
  if (event.data) {
    try {
      payload = event.data.json();        // works if object
    } catch (err) {
      console.warn('Push payload not JSON – using text');
      payload = { body: event.data.text() };   // string fallback
    }
  }

  const title = payload.title || '🔔 Notificación';
  const options = {
    body:  payload.body || '',
    icon:  '/static/logo-192.png',
    data:  { url: payload.url || '/' }    // click-through
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data.url || '/';
  event.waitUntil(clients.openWindow(url));
});
