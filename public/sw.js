self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => { if(e.request.method === 'GET' && new URL(e.request.url).origin === location.origin && !e.request.url.includes('/ws')) e.respondWith(fetch(e.request).catch(() => new Response('You are offline. Retro Blox needs a connection to play.', {status:503, headers:{'Content-Type':'text/plain'}}))); });
