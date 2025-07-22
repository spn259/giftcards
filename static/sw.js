self.addEventListener('install', event => {
  // Optionally pre-cache assets here
  console.log('SW installed');
});

self.addEventListener('activate', event => {
  console.log('SW activated');
});

// Handle incoming push messages
self.addEventListener('push', event => {
  console.log('Push received:', event);
  let data = { title: 'Nuevo insumo', body: 'Tienes una nueva asignación' };

  // Try to parse JSON payload if provided
  if (event.data) {
    try { data = event.data.json(); }
    catch(e) { console.warn('Push payload not JSON'); }
  }

  const options = {
    body:       data.body,
    icon:       '/static/icons-192.png',
    badge:      '/static/icons-192.png',
    data:       data,          // accessible in notificationclick
    vibrate:    [100, 50, 100] // mobile vibration pattern
  };

  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

// Optional: handle clicks on notifications
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.openWindow('/admin/insumos')  // focus or open your app
  );
});
