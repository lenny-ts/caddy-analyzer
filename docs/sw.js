/* caddy-analyzer docs — stale-while-revalidate service worker */
var CACHE = "caddy-docs-v29";
var ASSETS = [
    "index.html",
    "installation.html",
    "sources.html",
    "subcommands.html",
    "security.html",
    "tui-html.html",
    "404.html",
    "demo.html",
    "search-index.json",
    "styles.min.css?v=29",
    "docs.min.js?v=29",
    "manifest.json",
    "og-image.svg",
    "og-image.png",
    "icon.svg",
    "icon-192.png",
    "icon-512.png",
    "apple-touch-icon.png"
];

self.addEventListener("install", function (e) {
    e.waitUntil(
        caches.open(CACHE).then(function (c) {
            return c.addAll(ASSETS).catch(function () {});
        })
    );
    self.skipWaiting();
});

self.addEventListener("activate", function (e) {
    e.waitUntil(
        caches.keys().then(function (keys) {
            return Promise.all(
                keys.filter(function (k) { return k !== CACHE; })
                    .map(function (k) { return caches.delete(k); })
            );
        })
    );
    self.clients.claim();
});

self.addEventListener("fetch", function (e) {
    if (e.request.method !== "GET") return;
    var url = new URL(e.request.url);
    if (url.origin !== self.location.origin) return;
    e.respondWith(
        caches.open(CACHE).then(function (c) {
            return c.match(e.request).then(function (cached) {
                var fetcher = fetch(e.request).then(function (resp) {
                    if (resp && resp.status === 200 && resp.type === "basic") {
                        c.put(e.request, resp.clone()).catch(function () {});
                    }
                    return resp;
                }).catch(function () {
                    if (cached) return cached;
                    if (e.request.mode === "navigate") return c.match("404.html");
                });
                return cached || fetcher;
            });
        })
    );
});
