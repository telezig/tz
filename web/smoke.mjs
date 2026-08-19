// smoke.mjs — headless POC1 smoke test.
//
// Loads tz-db.wasm in a JS runtime (bun/deno/node) with a *memory-backed* mock
// of the OPFS backend, then verifies the full sqlite-over-custom-VFS path:
//   - sqlite3_os_init registers the OPFS VFS
//   - create schema, insert N rows in a transaction, COUNT them
//   - close + reopen the database, assert rows persisted
//   - paged SELECT
//
// This runs in CI without a browser. The same wasm module is used by the
// browser benchmark (web/db-bench-worker.js) with a real FileSystemSyncAccessHandle
// backend — the only difference is the JS side of the VFS.
//
// Usage: bun run smoke.mjs [path-to-tz-db.wasm] [N]

import { readFileSync } from 'node:fs';

const wasmPath = process.argv[2] ?? './zig-out/web/tz-db.wasm';
const N = parseInt(process.argv[3] ?? '1000', 10);

// --- memory-backed OPFS mock ---
// Files are just Uint8Arrays that grow on demand, exactly like a sparse file.
const files = new Map(); // name -> { bytes: Uint8Array }
globalThis.__files = files; // exposed for smoke-test diagnostics
const deleted = new Set();
let nextFd = 1;
const fds = new Map(); // fd -> name

function ensure(name, create) {
  if (deleted.has(name)) deleted.delete(name);
  if (!files.has(name)) {
    if (!create) return false;
    files.set(name, { bytes: new Uint8Array(0) });
  }
  return true;
}

function grow(file, offset, len) {
  const need = offset + len;
  if (file.bytes.length >= need) return;
  const nb = new Uint8Array(Math.max(need, file.bytes.length * 2, 4096));
  nb.set(file.bytes);
  file.bytes = nb;
}

let memory; // set after instantiation

const imports = {
  env: {
    js_opfs_open: (namePtr, nameLen, create) => {
      const name = new TextDecoder().decode(new Uint8Array(memory.buffer, namePtr, nameLen));
      console.log(`  [vfs] open "${name}" create=${create}`);
      if (!ensure(name, create)) return -1;
      const fd = nextFd++;
      fds.set(fd, name);
      return fd;
    },
    js_opfs_delete: (namePtr, nameLen) => {
      const name = new TextDecoder().decode(new Uint8Array(memory.buffer, namePtr, nameLen));
      deleted.add(name);
      files.delete(name);
      for (const [fd, nm] of fds) if (nm === name) fds.delete(fd);
      return 0;
    },
    js_opfs_access: (namePtr, nameLen) => {
      const name = new TextDecoder().decode(new Uint8Array(memory.buffer, namePtr, nameLen));
      if (deleted.has(name)) return 0;
      if (name.endsWith('-journal')) return 0; // never report hot journal
      return files.has(name) ? 1 : 0;
    },
    js_opfs_read: (fd, offset, bufPtr, len) => {
      const name = fds.get(fd);
      const file = files.get(name);
      if (!file) return -1;
      const buf = new Uint8Array(memory.buffer, bufPtr, len);
      const start = Number(offset);
      const avail = Math.max(0, Math.min(len, file.bytes.length - start));
      if (avail > 0) buf.set(file.bytes.subarray(start, start + avail));
      return avail;
    },
    js_opfs_write: (fd, offset, bufPtr, len) => {
      const name = fds.get(fd);
      const file = files.get(name);
      if (!file) return -1;
      const src = new Uint8Array(memory.buffer, bufPtr, len);
      grow(file, Number(offset), len);
      file.bytes.set(src, Number(offset));
      return len;
    },
    js_opfs_truncate: (fd, size) => {
      const name = fds.get(fd);
      const file = files.get(name);
      if (!file) return -1;
      const s = Number(size);
      if (s < file.bytes.length) {
        const nb = new Uint8Array(s);
        nb.set(file.bytes.subarray(0, s));
        file.bytes = nb;
      }
      return 0;
    },
    js_opfs_size: (fd) => {
      const name = fds.get(fd);
      const file = files.get(name);
      return BigInt(file ? file.bytes.length : -1); // wasm i64 return
    },
    js_opfs_flush: () => 0,
    js_opfs_close: (fd) => {
      fds.delete(fd);
    },
    js_opfs_random: (ptr, len) => {
      crypto.getRandomValues(new Uint8Array(memory.buffer, ptr, len));
    },
    js_now_ms: () => BigInt(Math.floor(performance.now())), // wasm u64 return
  },
};

// --- load ---
const wasmBytes = readFileSync(wasmPath);
const module = await WebAssembly.instantiate(wasmBytes, imports);
const wasm = module.instance.exports;
memory = wasm.memory;

const textDecoder = new TextDecoder();

// Pass a JS string into wasm as (ptr, len); returns [ptr, len] with the memory
// still allocated — caller frees with wasm.tzdb_free(ptr, len).
function toWasmStr(s) {
  const bytes = new TextEncoder().encode(s);
  const ptr = wasm.tzdb_alloc(bytes.length);
  if (!ptr) throw new Error('tzdb_alloc failed');
  new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
  return [ptr, bytes.length];
}

// Run one exec with a JS string, freeing the input after.
function exec(db, sql) {
  const [p, l] = toWasmStr(sql);
  const rc = wasm.tzdb_exec(db, p, l);
  wasm.tzdb_free(p, l);
  return rc;
}

// Prepare one statement with a JS string, freeing the input after.
function prepare(db, sql) {
  const [p, l] = toWasmStr(sql);
  const st = wasm.tzdb_prepare(db, p, l);
  wasm.tzdb_free(p, l);
  return st;
}

// Open a database by name (must go through wasm memory, not a JS string).
function openDb(name) {
  const [p, l] = toWasmStr(name);
  const db = wasm.tzdb_open(p, l);
  wasm.tzdb_free(p, l);
  return db;
}

function assert(cond, msg) {
  if (!cond) {
    console.error(`FAIL: ${msg}`);
    process.exit(1);
  }
}

// --- init ---
const initRc = wasm.sqlite3_os_init();
assert(initRc === 0, `sqlite3_os_init rc=${initRc}`);

// --- phase 1: fresh db, schema + inserts ---
const db = openDb('test.db');
assert(db >= 0, `tzdb_open rc=${db}`);

const schema =
  'CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, peer_id INTEGER NOT NULL, from_id INTEGER NOT NULL, date INTEGER NOT NULL, message TEXT NOT NULL, media_type TEXT, media_data BLOB, out INTEGER NOT NULL DEFAULT 0, flags INTEGER NOT NULL DEFAULT 0);' +
  'CREATE INDEX IF NOT EXISTS idx_messages_peer_date ON messages(peer_id, date);';
console.log("  step: schema");
assert(exec(db, schema) === 0, "schema exec");

const insertSql = 'INSERT INTO messages (id, peer_id, from_id, date, message, out, flags) VALUES (?,?,?,?,?,?,?);';
const insStmt = prepare(db, insertSql);
assert(insStmt >= 0, 'prepare insert');
assert(exec(db, 'BEGIN TRANSACTION;') === 0, 'begin');
for (let i = 0; i < N; i++) {
  wasm.tzdb_reset(insStmt);
  wasm.tzdb_bind_int64(insStmt, 1, BigInt(i));
  wasm.tzdb_bind_int64(insStmt, 2, 123456789n);
  wasm.tzdb_bind_int64(insStmt, 3, 123456789n);
  wasm.tzdb_bind_int64(insStmt, 4, 1700000000n + BigInt(i));
  const msgPtr = wasm.tzdb_alloc(38);
  new Uint8Array(memory.buffer, msgPtr, 38).set(new TextEncoder().encode('Hello Telegram message from Zig SQLite'));
  wasm.tzdb_bind_text(insStmt, 5, msgPtr, 38);
  wasm.tzdb_free(msgPtr, 38);
  wasm.tzdb_bind_int(insStmt, 6, 0);
  wasm.tzdb_bind_int(insStmt, 7, 0);
  const rc = wasm.tzdb_step(insStmt);
  assert(rc === 101, `insert step rc=${rc} at i=${i}`);
}
wasm.tzdb_finalize(insStmt);
assert(exec(db, 'COMMIT;') === 0, 'commit');

// --- phase 2: count within open db ---
const countSql = 'SELECT COUNT(*) FROM messages WHERE peer_id = ?;';
const cntStmt = prepare(db, countSql);
wasm.tzdb_bind_int64(cntStmt, 1, 123456789n);
assert(wasm.tzdb_step(cntStmt) === 100, 'count step');
const liveCount = wasm.tzdb_column_int64(cntStmt, 0);
assert(Number(liveCount) === N, `count=${liveCount} expected ${N}`);
wasm.tzdb_finalize(cntStmt);

// --- phase 3: persistence — close, reopen, count again ---
assert(wasm.tzdb_close(db) === 0, 'close');

// sanity: mock should still hold the file
if (globalThis.__files) {
  const entries = [...globalThis.__files.entries()];
  console.log('  mock files after close:', entries.map(([k, v]) => `${k}(${v.bytes.length}b)`).join(', '));
}

const db2 = openDb('test.db');
assert(db2 >= 0, 'reopen');
const cnt2 = prepare(db2, countSql);
wasm.tzdb_bind_int64(cnt2, 1, 123456789n);
const rc2 = wasm.tzdb_step(cnt2);
if (rc2 !== 100) {
  const ebuf = wasm.tzdb_alloc(256);
  const en = wasm.tzdb_errmsg(db2, ebuf, 256);
  console.error(`reopen count step rc=${rc2} err=${JSON.stringify(textDecoder.decode(new Uint8Array(memory.buffer, ebuf, en)))}`);
  wasm.tzdb_free(ebuf, 256);
}
assert(rc2 === 100, `reopen count step rc=${rc2}`);
const reopenCount = wasm.tzdb_column_int64(cnt2, 0);
assert(Number(reopenCount) === N, `reopen count=${reopenCount} expected ${N}`);
wasm.tzdb_finalize(cnt2);

// --- phase 4: paged select ---
const pageSql = 'SELECT id, message FROM messages WHERE peer_id = ? ORDER BY date DESC LIMIT 10 OFFSET 0;';
const pg = prepare(db2, pageSql);
wasm.tzdb_bind_int64(pg, 1, 123456789n);
let rows = 0;
while (wasm.tzdb_step(pg) === 100) {
  const id = wasm.tzdb_column_int64(pg, 0);
  const blen = wasm.tzdb_column_bytes(pg, 1);
  const buf = wasm.tzdb_alloc(blen);
  const got = wasm.tzdb_column_blob(pg, 1, buf, blen);
  const msg = textDecoder.decode(new Uint8Array(memory.buffer, buf, got));
  wasm.tzdb_free(buf, blen);
  if (rows === 0) assert(msg.startsWith('Hello'), 'first page row message');
  assert(Number(id) === N - 1 - rows, `page row id=${id}`);
  rows++;
}
assert(rows === 10, `page rows=${rows}`);
wasm.tzdb_finalize(pg);

wasm.tzdb_close(db2);

// --- phase 5: benchmark entry ---
const benchDb = openDb('bench.db');
assert(benchDb >= 0, 'bench open');
const outPtr = wasm.tzdb_alloc(512);
const written = wasm.tzdb_bench(benchDb, 1000, outPtr, 512);
assert(written > 0, `tzdb_bench written=${written}`);
const report = JSON.parse(textDecoder.decode(new Uint8Array(memory.buffer, outPtr, written)));
assert(report.ok === true, `bench ok=${report.ok}`);
assert(Number(report.rows) === 1000, `bench rows=${report.rows}`);
wasm.tzdb_free(outPtr, 512);
wasm.tzdb_close(benchDb);

console.log(`PASS: sqlite-over-VFS smoke test (${N} rows)`);
console.log(`  live count=${liveCount} reopen count=${reopenCount} paged rows=${rows}`);
console.log(`  bench: insert=${report.insert_ms}ms count=${report.count_ms}ms page=${report.page_ms}ms`);
