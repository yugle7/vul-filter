const APP_PREFIX = "vuln-triage";
const CACHE_VERSION = "18";
const CACHE = `${APP_PREFIX}-${CACHE_VERSION}`;

const APP_SHELL = [
    "./",
    "index.html",
    "styles.css",
    "script.js",
    "manifest.json",
    "sprite.svg",
    "favicon.svg",
    "icons/icon-192.png",
    "icons/icon-512.png",
    "icons/icon-192-maskable.png",
    "icons/icon-512-maskable.png",
];

// Install: cache the application shell
self.addEventListener("install", (e) => {
    e.waitUntil(
        caches
            .open(CACHE)
            .then((cache) => cache.addAll(APP_SHELL.map((url) => new Request(url, {cache: "reload"}))))
            .then(() => self.skipWaiting()),
    );
});

// Activate: remove caches of previous versions
self.addEventListener("activate", (e) => {
    e.waitUntil(
        caches
            .keys()
            .then((keys) =>
                Promise.all(
                    keys
                        .filter((key) => key.startsWith(APP_PREFIX) && key !== CACHE)
                        .map((key) => caches.delete(key)),
                ),
            )
            .then(() => self.clients.claim()),
    );
});

// Stale-while-revalidate: answer from the cache at once and refresh it in the background,
// so a new version is picked up on the next launch without reloading the open page
const staleWhileRevalidate = async (e) => {
    const cache = await caches.open(CACHE);
    const cached = await cache.match(e.request, {ignoreSearch: true});
    const fresh = fetch(e.request).then((response) => {
        if (response.ok) cache.put(e.request, response.clone());
        return response;
    });
    if (!cached) return fresh;
    e.waitUntil(fresh.catch(() => {}));
    return cached;
};

self.addEventListener("fetch", (e) => {
    const url = new URL(e.request.url);
    if (e.request.method !== "GET" || url.origin !== location.origin) return;
    e.respondWith(staleWhileRevalidate(e));
});
