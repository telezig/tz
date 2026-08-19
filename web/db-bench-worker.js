// db-bench-worker.js — POC1 benchmark worker.
//
// Runs the same message-history workload against two storage backends:
//   A) SQLite compiled to wasm32-freestanding, persisted through OPFS
//      FileSystemSyncAccessHandle via the custom VFS (src/db/vfs_opfs.zig)
//   B) IndexedDB (baseline, pure JS)
//
// IMPORTANT: obtaining a FileSystemSyncAccessHandle is ASYNC
// (getFileHandle + createSyncAccessHandle return Promises), while sqlite's
// xOpen is a synchronous call. The JS side therefore *pre-opens* every file
// the database may touch (main db, journal) before handing control to wasm;
// js_opfs_open then only does a synchronous table lookup.
//
// This is exactly the glue a production @telezig/web worker would provide.

let postLog = () => {};

function capabilityStatus() {
  try {
    if (!navigator.storage || typeof navigator.storage.getDirectory !== 'function') {
      return 'no navigator.storage.getDirectory';
    }
    return 'ok';
  } catch (e) {
    return `error: ${e.message}`;
  }
}

class OpfsBackend {
  constructor(rootDirHandle) {
    this.root = rootDirHandle;
    this.handles = new Map();  // name -> { sync, closed }
    this.fds = new Map();      // fd -> name
    this.deleted = new Set();  // names logically deleted
    this.nextFd = 1;
  }

  // Async: open (or create) a file and cache its sync handle under `name`.
  async preload(name, create) {
    const trimmed = name.replace(/^\.\//, '');
    if (this.deleted.has(trimmed)) {
      // Stale entry from a previous xDelete: rebuild empty.
      this.deleted.delete(trimmed);
      try {
        const h = await this.root.getFileHandle(trimmed, { create: true });
        const s = await h.createSyncAccessHandle();
        s.truncate(0);
        s.close();
      } catch (e) {
        postLog(`opfs: rebuild stale '${trimmed}' failed: ${e.message}`);
      }
    }
    let fileHandle;
    try {
      fileHandle = await this.root.getFileHandle(trimmed, { create });
    } catch (e) {
      return false;
    }
    let sync;
    try {
      sync = await fileHandle.createSyncAccessHandle();
    } catch (e) {
      return false;
    }
    this.handles.set(trimmed, { sync, closed: false });
    return true;
  }

  // Sync: allocate an fd for `name`. Returns -1 if not preloaded.
  // sqlite opens/closes the same file repeatedly (journal especially), so a
  // previously-deleted handle is reactivated (xDelete marks + truncates; a
  // later xOpen with CREATE clears the mark).
  open(name, create) {
    const trimmed = name.replace(/^\.\//, '');
    const entry = this.handles.get(trimmed);
    if (!entry) return -1;
    if (this.deleted.has(trimmed)) {
      // Previous xDelete; sqlite is re-creating the file now.
      if (!create) return -1;
      this.deleted.delete(trimmed);
      try {
        entry.sync.truncate(0);
      } catch (e) {
        return -1;
      }
    }
    const fd = this.nextFd++;
    this.fds.set(fd, trimmed);
    return fd;
  }

  read(fd, offset, dst) {
    const name = this.fds.get(fd);
    if (!name) return -1;
    const entry = this.handles.get(name);
    if (!entry || entry.closed) return -1;
    try {
      return entry.sync.read(dst, { at: Number(offset) });
    } catch (e) {
      return -1;
    }
  }

  write(fd, offset, src) {
    const name = this.fds.get(fd);
    if (!name) return -1;
    const entry = this.handles.get(name);
    if (!entry || entry.closed) return -1;
    try {
      return entry.sync.write(src, { at: Number(offset) });
    } catch (e) {
      return -1;
    }
  }

  truncate(fd, size) {
    const name = this.fds.get(fd);
    if (!name) return -1;
    const entry = this.handles.get(name);
    if (!entry || entry.closed) return -1;
    try {
      entry.sync.truncate(Number(size));
      return 0;
    } catch (e) {
      return -1;
    }
  }

  size(fd) {
    const name = this.fds.get(fd);
    if (!name) return -1;
    const entry = this.handles.get(name);
    if (!entry || entry.closed) return -1;
    try {
      return entry.sync.getSize();
    } catch (e) {
      return -1;
    }
  }

  flush(fd) {
    const name = this.fds.get(fd);
    if (!name) return -1;
    const entry = this.handles.get(name);
    if (!entry || entry.closed) return -1;
    try {
      entry.sync.flush();
      return 0;
    } catch (e) {
      return -1;
    }
  }

  close(fd) {
    const name = this.fds.get(fd);
    if (!name) return;
    // Keep the sync handle open (sqlite re-opens the same file by name);
    // just drop the fd mapping.
    this.fds.delete(fd);
  }

  // Logical delete: OPFS cannot remove synchronously, so mark the name and
  // schedule the real removal. xAccess() consults the mark, so sqlite sees
  // the file as gone immediately. The sync handle is truncated so stale data
  // never surfaces if sqlite re-creates the file.
  delete(name) {
    const trimmed = name.replace(/^\.\//, '');
    this.deleted.add(trimmed);
    for (const [fd, nm] of this.fds) {
      if (nm === trimmed) this.fds.delete(fd);
    }
    const entry = this.handles.get(trimmed);
    if (entry) {
      try {
        entry.sync.truncate(0);
        entry.sync.flush();
      } catch (e) {}
    }
    (async () => {
      try {
        await this.root.removeEntry(trimmed, { recursive: false });
        this.deleted.delete(trimmed);
      } catch (e) {
        setTimeout(() => this.deleted.delete(trimmed), 50);
      }
    })();
    return 0;
  }

  access(name) {
    const trimmed = name.replace(/^\.\//, '');
    if (this.deleted.has(trimmed)) return 0;
    // Never report journal files as existing: OPFS preloads them (they are
    // created before sqlite asks), so reporting them would make sqlite think
    // a previous transaction crashed (hot journal) and try to roll it back —
    // which fails on an empty journal ("disk I/O error"). sqlite creates and
    // truncates journal files itself on transaction start, so this is safe.
    if (trimmed.endsWith('-journal')) return 0;
    const entry = this.handles.get(trimmed);
    return entry && !entry.closed ? 1 : 0;
  }
}

// --- WASM loading + import wiring ---
let gWasmBytes = null;

async function loadSqliteWasm(opfs) {
  const response = await fetch('tz-db.wasm');
  if (!response.ok) throw new Error(`fetch tz-db.wasm: HTTP ${response.status}`);
  const wasmBytes = await response.arrayBuffer();
  gWasmBytes = wasmBytes;

  const textDecoder = new TextDecoder();
  const imports = {
    env: {
      js_opfs_open: (namePtr, nameLen, create) => {
        const name = textDecoder.decode(new Uint8Array(memory.buffer, namePtr, nameLen));
        return opfs.open(name, create);
      },
      js_opfs_delete: (namePtr, nameLen) => {
        const name = textDecoder.decode(new Uint8Array(memory.buffer, namePtr, nameLen));
        return opfs.delete(name);
      },
      js_opfs_access: (namePtr, nameLen) => {
        const name = textDecoder.decode(new Uint8Array(memory.buffer, namePtr, nameLen));
        return opfs.access(name);
      },
      js_opfs_read: (fd, offset, bufPtr, len) => {
        const buf = new Uint8Array(memory.buffer, bufPtr, len);
        return opfs.read(fd, offset, buf);
      },
      js_opfs_write: (fd, offset, bufPtr, len) => {
        const buf = new Uint8Array(memory.buffer, bufPtr, len);
        return opfs.write(fd, offset, buf);
      },
      js_opfs_truncate: (fd, size) => opfs.truncate(fd, size),
      // wasm declares these as i64/u64 — JS must return BigInt
      js_opfs_size: (fd) => BigInt(opfs.size(fd)),
      js_opfs_flush: (fd) => opfs.flush(fd),
      js_opfs_close: (fd) => opfs.close(fd),
      js_opfs_random: (ptr, len) => {
        crypto.getRandomValues(new Uint8Array(memory.buffer, ptr, len));
      },
      js_now_ms: () => BigInt(Math.floor(performance.now())),
    },
  };

  const module = await WebAssembly.instantiate(wasmBytes, imports);
  const wasm = module.instance.exports;
  const memory = wasm.memory;
  return { wasm, memory };
}

// --- IndexedDB baseline ---

function openIdb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('tz-bench', 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('messages')) {
        db.createObjectStore('messages', { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbPutAll(db, n) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction('messages', 'readwrite');
    const store = tx.objectStore('messages');
    for (let i = 0; i < n; i++) {
      store.put({ id: i, peer_id: 123456789, date: 1700000000 + i, message: 'Hello Telegram message from JS IndexedDB' });
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function idbCount(db) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction('messages', 'readonly');
    const req = tx.objectStore('messages').count();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbPage(db, offset, limit) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction('messages', 'readonly');
    const req = tx.objectStore('messages').openCursor(null, 'prev');
    let skipped = 0;
    let got = 0;
    req.onsuccess = () => {
      const cursor = req.result;
      if (!cursor || got >= limit) return resolve(got);
      if (skipped < offset) { skipped++; cursor.continue(); return; }
      got++;
      cursor.continue();
    };
    req.onerror = () => reject(req.error);
  });
}

// --- benchmark drivers ---

// Strings must be copied into wasm memory before being passed to wasm exports.
function wasmStr(wasm, memory, s) {
  const bytes = new TextEncoder().encode(s);
  const ptr = wasm.tzdb_alloc(bytes.length);
  if (!ptr) throw new Error('tzdb_alloc failed');
  new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
  return [ptr, bytes.length];
}

async function benchSqlite(n, { wasm, memory, opfs }) {
  // Fresh db each run: pre-open main db + journal (both async), then run.
  opfs.deleted.clear();
  opfs.fds.clear();
  opfs.handles.clear();
  opfs.nextFd = 1;
  await opfs.root.removeEntry('tz-poc1.db', { recursive: false }).catch(() => {});

  await opfs.preload('tz-poc1.db', true);
  await opfs.preload('tz-poc1.db-journal', true);

  const dbName = 'tz-poc1.db';
  const [dbNamePtr, dbNameLen] = wasmStr(wasm, memory, dbName);
  const db = wasm.tzdb_open(dbNamePtr, dbNameLen);
  wasm.tzdb_free(dbNamePtr, dbNameLen);
  if (db < 0) throw new Error('tzdb_open failed');

  const outLen = 512;
  const outPtr = wasm.tzdb_alloc(outLen);
  if (!outPtr) throw new Error('tzdb_alloc failed');
  const written = wasm.tzdb_bench(db, n, outPtr, outLen);
  if (written < 0) throw new Error('tzdb_bench failed');
  const reportStr = new TextDecoder().decode(new Uint8Array(memory.buffer, outPtr, written));
  wasm.tzdb_free(outPtr, outLen);
  const report = JSON.parse(reportStr);

  // Persistence check: close db, close the handle, reopen fresh (preload again),
  // count rows — proves data survived a close/reopen cycle in OPFS.
  wasm.tzdb_close(db);
  for (const [fd] of opfs.fds) opfs.close(fd);
  opfs.fds.clear();

  await opfs.preload('tz-poc1.db', false);
  await opfs.preload('tz-poc1.db-journal', true);
  const [dbNamePtr2, dbNameLen2] = wasmStr(wasm, memory, dbName);
  const db2 = wasm.tzdb_open(dbNamePtr2, dbNameLen2);
  wasm.tzdb_free(dbNamePtr2, dbNameLen2);
  if (db2 < 0) throw new Error('reopen failed');
  const countSql = 'SELECT COUNT(*) FROM messages WHERE peer_id = 123456789;';
  const [sqlPtr, sqlLen] = wasmStr(wasm, memory, countSql);
  const stmt = wasm.tzdb_prepare(db2, sqlPtr, sqlLen);
  wasm.tzdb_free(sqlPtr, sqlLen);
  if (stmt < 0) {
    // diagnostics: read sqlite error message
    const ebuf = wasm.tzdb_alloc(256);
    const en = wasm.tzdb_errmsg(db2, ebuf, 256);
    const emsg = new TextDecoder().decode(new Uint8Array(memory.buffer, ebuf, en));
    wasm.tzdb_free(ebuf, 256);
    throw new Error(`prepare failed after reopen: ${emsg}`);
  }
  const rc = wasm.tzdb_step(stmt);
  let reopenCount = -1;
  if (rc === 100) reopenCount = wasm.tzdb_column_int64(stmt, 0);
  wasm.tzdb_finalize(stmt);
  wasm.tzdb_close(db2);

  // Bundle size (gzip via CompressionStream when available).
  let bundleGzipKb = -1;
  try {
    if (typeof CompressionStream === 'function') {
      const stream = new Blob([gWasmBytes]).stream().pipeThrough(new CompressionStream('gzip'));
      const buf = await new Response(stream).arrayBuffer();
      bundleGzipKb = Math.round(buf.byteLength / 1024);
    }
  } catch (e) {}

  return {
    insert_ms: report.insert_ms,
    count_ms: report.count_ms,
    page_ms: report.page_ms,
    rows: report.rows,
    ok: report.ok,
    reopen_count: reopenCount,
    bundle_gzip_kb: bundleGzipKb,
  };
}

async function benchIndexedDb(n) {
  const db = await openIdb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction('messages', 'readwrite');
      tx.objectStore('messages').clear();
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });

    const t0 = performance.now();
    await idbPutAll(db, n);
    const insertMs = performance.now() - t0;

    const t1 = performance.now();
    const count = await idbCount(db);
    const countMs = performance.now() - t1;

    const t2 = performance.now();
    for (let page = 0; page < 10; page++) {
      await idbPage(db, page * 100, 100);
    }
    const pageMs = performance.now() - t2;

    return { insert_ms: insertMs, count_ms: countMs, page_ms: pageMs, rows: count, ok: count === n };
  } finally {
    db.close();
  }
}

// --- main ---

self.onmessage = async (e) => {
  if (e.data.type !== 'run') return;
  const n = e.data.n || 1000;
  postLog = (msg) => self.postMessage({ type: 'log', msg });

  try {
    const status = capabilityStatus();
    if (status !== 'ok') {
      self.postMessage({ type: 'result', ok: false, error: `OPFS unavailable: ${status}` });
      return;
    }
    const root = await navigator.storage.getDirectory();
    const opfs = new OpfsBackend(root);

    postLog('Loading tz-db.wasm...');
    const { wasm, memory } = await loadSqliteWasm(opfs);

    if (typeof wasm.sqlite3_os_init === 'function') {
      const rc = wasm.sqlite3_os_init();
      if (rc !== 0) throw new Error(`sqlite3_os_init failed rc=${rc}`);
    }

    postLog(`Running sqlite (OPFS) benchmark with n=${n}...`);
    const sqlite = await benchSqlite(n, { wasm, memory, opfs });

    postLog('Running IndexedDB baseline...');
    const idb = await benchIndexedDb(n);

    self.postMessage({ type: 'result', ok: true, sqlite, idb });
  } catch (err) {
    self.postMessage({ type: 'result', ok: false, error: err.message, stack: err.stack });
  }
};
