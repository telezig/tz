// Static file server for testing the tz web demos (bun).
// Serves zig-out/web/ with correct MIME types + COOP/COEP not needed for OPFS.
const { serve } = Bun;
import { readFileSync, statSync } from 'node:fs';
import { join, normalize, resolve } from 'node:path';

const root = resolve(process.argv[2] ?? './zig-out/web');
const port = parseInt(process.argv[3] ?? '8731', 10);

const mime = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.wasm': 'application/wasm',
  '.json': 'application/json',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

serve({
  port,
  async fetch(req) {
    const url = new URL(req.url);
    let path = normalize(decodeURIComponent(url.pathname));
    if (path === '/' || path === '/index.html') path = '/index.html';
    const file = join(root, path);
    // prevent path traversal
    if (!file.startsWith(root)) return new Response('forbidden', { status: 403 });
    try {
      const st = statSync(file);
      if (!st.isFile()) return new Response('not found', { status: 404 });
      const ext = file.slice(file.lastIndexOf('.'));
      const body = readFileSync(file);
      return new Response(body, {
        headers: {
          'Content-Type': mime[ext] ?? 'application/octet-stream',
          'Cache-Control': 'no-store',
          // OPFS requires a secure context; localhost counts, but be explicit.
          'Cross-Origin-Opener-Policy': 'same-origin',
          'Cross-Origin-Embedder-Policy': 'require-corp',
        },
      });
    } catch (e) {
      return new Response('not found', { status: 404 });
    }
  },
});

console.log(`serving ${root} at http://127.0.0.1:${port}/`);
console.log(`  benchmark page: http://127.0.0.1:${port}/db-bench.html`);
console.log(`  mtproto demo:   http://127.0.0.1:${port}/index.html`);
