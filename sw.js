// Decrypts the encrypted vault on the fly so the original pages, links and video work unchanged.
const SCOPE = new URL(self.registration.scope);
let state = null;
const memo = new Map();

function idbGetKey() {
  return new Promise((resolve) => {
    const open = indexedDB.open('handoff-vault', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('k');
    open.onerror = () => resolve(null);
    open.onsuccess = () => {
      const tx = open.result.transaction('k', 'readonly');
      const get = tx.objectStore('k').get('key');
      get.onsuccess = () => resolve(get.result || null);
      get.onerror = () => resolve(null);
    };
  });
}

async function decrypt(key, buf) {
  const iv = new Uint8Array(buf.slice(0, 12));
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, buf.slice(12));
}

async function load() {
  if (state) return state;
  const key = await idbGetKey();
  if (!key) return null;
  const r = await fetch(new URL('vault/manifest.bin', SCOPE), { cache: 'no-cache' });
  try {
    const man = JSON.parse(new TextDecoder().decode(await decrypt(key, await r.arrayBuffer())));
    state = { key, man };
    return state;
  } catch (e) {
    return null;
  }
}

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('message', (e) => { if (e.data === 'reset') { state = null; memo.clear(); } });

const PASS = new Set(['', 'index.html', 'sw.js', '404.html', 'robots.txt', '.nojekyll']);

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== SCOPE.origin || e.request.method !== 'GET') return;
  if (!url.pathname.startsWith(SCOPE.pathname)) return;
  const rel = decodeURIComponent(url.pathname.slice(SCOPE.pathname.length)).normalize('NFC');
  if (PASS.has(rel) || rel.startsWith('vault/')) return;
  e.respondWith(serve(rel, e.request));
});

async function serve(rel, req) {
  const st = await load();
  if (!st) return Response.redirect(new URL('index.html?next=' + encodeURIComponent(rel), SCOPE).href, 302);
  const ent = st.man.files[rel];
  if (!ent) return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  let body = memo.get(rel);
  if (!body) {
    const r = await fetch(new URL('vault/' + ent.id + '.bin', SCOPE));
    body = await decrypt(st.key, await r.arrayBuffer());
    if (ent.type.startsWith('video/')) memo.set(rel, body);
  }
  const size = body.byteLength;
  const range = req.headers.get('range');
  const m = range && /bytes=(\d*)-(\d*)/.exec(range);
  if (m) {
    let start, end;
    if (m[1] === '' && m[2] !== '') { start = Math.max(0, size - Number(m[2])); end = size - 1; }
    else { start = Number(m[1] || 0); end = m[2] ? Math.min(Number(m[2]), size - 1) : size - 1; }
    return new Response(body.slice(start, end + 1), {
      status: 206,
      headers: { 'Content-Type': ent.type, 'Content-Range': `bytes ${start}-${end}/${size}`,
                 'Content-Length': String(end - start + 1), 'Accept-Ranges': 'bytes' },
    });
  }
  return new Response(body, { status: 200, headers: { 'Content-Type': ent.type, 'Content-Length': String(size), 'Accept-Ranges': 'bytes' } });
}
