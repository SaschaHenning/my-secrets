// Minimal service worker, present ONLY to satisfy PWA installability
// criteria (Chrome/Edge require a registered service worker with a
// fetch handler before offering "Install app"). It is a pure network
// passthrough and MUST stay that way: this app can render decrypted
// secret values, and a Cache Storage entry for any response here would
// be an unencrypted, disk-persistent copy of whatever it cached, outside
// the audit log's visibility. Do not introduce any Cache Storage API
// usage in this file — see docs/SECURITY.md's Web UI section. (Also
// enforced by internal/web/web_test.go's TestSWJS_NeverCaches.)

self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request));
});
