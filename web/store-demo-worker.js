// store-demo-worker.js — message store demo over real OPFS.
//
// Loads tz-db.wasm and opens a SQLite database persisted through
// FileSystemSyncAccessHandle (the same VFS path POC1 validated). The main
// thread sends "store" / "history" messages; this worker answers from the
// database. Data survives page reloads because it lives in OPFS.

let postLog = () => {};

class OpfsBackend {
  constructor(rootDirHandle) {
    this.root = rootDirHandle;
    this.handles = new Map(); // name -> { sync }
    this.fds = new Map();     // fd -> name
    this.deleted = new Set();
    this.nextFd = 1;
  }

  async preload(name, create) {
    const trimmed = name.replace(/^\.\//, '');
    if (this.deleted.has(trimmed)) {
      this.deleted.delete(trimmed);
      try {
        const h = await this.root.getFileHandle(trimmed, { create: true });
        const s = await h.createSyncAccessHandle();
        s.truncate(0); s.close();
      } catch (e) { postLog(`rebuild stale '${trimmed}' failed: ${e.message}`); }
    }
    let fileHandle;
    try { fileHandle = await this.root.getFileHandle(trimmed, { create }); }
    catch (e) { return false; }
    let sync;
    try { sync = await fileHandle.createSyncAccessHandle(); }
    catch (e) { return false; }
    this.handles.set(trimmed, { sync });
    return true;
  }

  open(name, create) {
    const trimmed = name.replace(/^\.\//, '');
    const entry = this.handles.get(trimmed);
    if (!entry) return -1;
    if (this.deleted.has(trimmed)) {
      if (!create) return -1;
      this.deleted.delete(trimmed);
      try { entry.sync.truncate(0); } catch (e) { return -1; }
    }
    const fd = this.nextFd++;
    this.fds.set(fd, trimmed);
    return fd;
  }
  read(fd, offset, dst) {
    const e = this.handles.get(this.fds.get(fd));
    if (!e) return -1;
    try { return e.sync.read(dst, { at: Number(offset) }); } catch (e2) { return -1; }
  }
  write(fd, offset, src) {
    const e = this.handles.get(this.fds.get(fd));
    if (!e) return -1;
    try { return e.sync.write(src, { at: Number(offset) }); } catch (e2) { return -1; }
  }
  truncate(fd, size) {
    const e = this.handles.get(this.fds.get(fd));
    if (!e) return -1;
    try { e.sync.truncate(Number(size)); return 0; } catch (e2) { return -1; }
  }
  size(fd) {
    const e = this.handles.get(this.fds.get(fd));
    if (!e) return -1;
    try { return e.sync.getSize(); } catch (e2) { return -1; }
  }
  flush(fd) {
    const e = this.handles.get(this.fds.get(fd));
    if (!e) return -1;
    try { e.sync.flush(); return 0; } catch (e2) { return -1; }
  }
  close(fd) { this.fds.delete(fd); }
  delete(name) {
    const trimmed = name.replace(/^\.\//, '');
    this.deleted.add(trimmed);
    for (const [fd, nm] of this.fds) if (nm === trimmed) this.fds.delete(fd);
    const e = this.handles.get(trimmed);
    if (e) { try { e.sync.truncate(0); e.sync.flush(); } catch (e2) {} }
    (async () => {
      try { await this.root.removeEntry(trimmed, { recursive: false }); this.deleted.delete(trimmed); }
      catch (e) { setTimeout(() => this.deleted.delete(trimmed), 50); }
    })();
    return 0;
  }
  access(name) {
    const trimmed = name.replace(/^\.\//, '');
    if (this.deleted.has(trimmed)) return 0;
    if (trimmed.endsWith('-journal')) return 0;
    return this.handles.has(trimmed) ? 1 : 0;
  }
}

let wasm = null, memory = null, db = -1;
let counter = 0;

function wasmStr(s) {
  const b = new TextEncoder().encode(s);
  const p = wasm.tzdb_alloc(b.length);
  if (!p) throw new Error('tzdb_alloc failed');
  new Uint8Array(memory.buffer, p, b.length).set(b);
  return [p, b.length];
}
function exec(sql) {
  const [p, l] = wasmStr(sql);
  const rc = wasm.tzdb_exec(db, p, l);
  wasm.tzdb_free(p, l);
  return rc;
}
function prepare(sql) {
  const [p, l] = wasmStr(sql);
  const st = wasm.tzdb_prepare(db, p, l);
  wasm.tzdb_free(p, l);
  return st;
}

async function init() {
  const root = await navigator.storage.getDirectory();
  const opfs = new OpfsBackend(root);

  const resp = await fetch('tz-db.wasm');
  if (!resp.ok) throw new Error('fetch tz-db.wasm: ' + resp.status);
  const bytes = await resp.arrayBuffer();
  const dec = new TextDecoder();

  const imports = { env: {
    js_opfs_open: (p, l, create) => {
      const name = dec.decode(new Uint8Array(memory.buffer, p, l));
      return opfs.open(name, create);
    },
    js_opfs_delete: (p, l) => {
      const name = dec.decode(new Uint8Array(memory.buffer, p, l));
      return opfs.delete(name);
    },
    js_opfs_access: (p, l) => {
      const name = dec.decode(new Uint8Array(memory.buffer, p, l));
      return opfs.access(name);
    },
    js_opfs_read: (fd, off, bp, len) => {
      const buf = new Uint8Array(memory.buffer, bp, len);
      return opfs.read(fd, off, buf);
    },
    js_opfs_write: (fd, off, bp, len) => {
      const buf = new Uint8Array(memory.buffer, bp, len);
      return opfs.write(fd, off, buf);
    },
    js_opfs_truncate: (fd, size) => opfs.truncate(fd, size),
    js_opfs_size: (fd) => BigInt(opfs.size(fd)),
    js_opfs_flush: (fd) => opfs.flush(fd),
    js_opfs_close: (fd) => opfs.close(fd),
    js_opfs_random: (p, l) => crypto.getRandomValues(new Uint8Array(memory.buffer, p, l)),
    js_now_ms: () => BigInt(Math.floor(performance.now())),
  }};

  const mod = await WebAssembly.instantiate(bytes, imports);
  wasm = mod.instance.exports;
  memory = wasm.memory;

  if (typeof wasm.sqlite3_os_init === 'function') {
    const rc = wasm.sqlite3_os_init();
    if (rc !== 0) throw new Error('sqlite3_os_init rc=' + rc);
  }

  // Pre-open main db + journal (sqlite will open/close them repeatedly).
  await opfs.preload('tz_store.db', true);
  await opfs.preload('tz_store.db-journal', true);
  const [dp, dl] = wasmStr('tz_store.db');
  db = wasm.tzdb_open(dp, dl);
  wasm.tzdb_free(dp, dl);
  if (db < 0) throw new Error('tzdb_open failed');

  exec(
    'CREATE TABLE IF NOT EXISTS messages (' +
    'id INTEGER PRIMARY KEY, peer_id INTEGER NOT NULL, from_id INTEGER NOT NULL DEFAULT 0,' +
    'date INTEGER NOT NULL, message TEXT NOT NULL, media_type TEXT, media_data BLOB,' +
    'out INTEGER NOT NULL DEFAULT 0, flags INTEGER NOT NULL DEFAULT 0);' +
    'CREATE INDEX IF NOT EXISTS idx_messages_peer_date ON messages(peer_id, date DESC);'
  );
}

function storeMessage(peerId, text, fromId, out) {
  counter++;
  const id = Date.now() * 1000 + counter;
  const date = Math.floor(Date.now() / 1000);
  const st = prepare(
    'INSERT INTO messages (id, peer_id, from_id, date, message, out, flags) VALUES (?,?,?,?,?,?,?)' +
    ' ON CONFLICT(id) DO UPDATE SET message=excluded.message;'
  );
  wasm.tzdb_bind_int64(st, 1, BigInt(id));
  wasm.tzdb_bind_int64(st, 2, BigInt(peerId));
  wasm.tzdb_bind_int64(st, 3, BigInt(fromId));
  wasm.tzdb_bind_int64(st, 4, BigInt(date));
  const [mp, ml] = wasmStr(text);
  wasm.tzdb_bind_text(st, 5, mp, ml);
  wasm.tzdb_free(mp, ml);
  wasm.tzdb_bind_int(st, 6, out ? 1 : 0);
  wasm.tzdb_bind_int(st, 7, 0);
  const rc = wasm.tzdb_step(st);
  wasm.tzdb_finalize(st);
  if (rc !== 101) throw new Error('store step rc=' + rc);
  return id;
}

function loadHistory() {
  const rows = [];
  const st = prepare('SELECT id, peer_id, from_id, date, message, out FROM messages ORDER BY date DESC, id DESC LIMIT 100;');
  while (wasm.tzdb_step(st) === 100) {
    const id = wasm.tzdb_column_int64(st, 0);
    const peerId = wasm.tzdb_column_int64(st, 1);
    const fromId = wasm.tzdb_column_int64(st, 2);
    const date = wasm.tzdb_column_int64(st, 3);
    const blen = wasm.tzdb_column_bytes(st, 4);
    const buf = wasm.tzdb_alloc(blen);
    const got = wasm.tzdb_column_blob(st, 4, buf, blen);
    const text = new TextDecoder().decode(new Uint8Array(memory.buffer, buf, got));
    wasm.tzdb_free(buf, blen);
    const out = wasm.tzdb_column_int(st, 5);
    rows.push({ id: String(id), peerId: String(peerId), fromId: String(fromId), date: String(date), text, out: out !== 0 });
  }
  wasm.tzdb_finalize(st);
  return rows;
}

self.onmessage = async (e) => {
  const id = e.data._id;
  if (e.data.type === 'init') {
    try {
      await init();
      self.postMessage({ type: 'ready', _id: id });
    } catch (err) {
      self.postMessage({ type: 'error', message: err.message, stack: err.stack, _id: id });
    }
    return;
  }
  if (e.data.type === 'store') {
    try {
      const msgId = storeMessage(parseInt(e.data.peerId), e.data.text, e.data.fromId, !!e.data.out);
      self.postMessage({ type: 'stored', id: String(msgId), _id: id });
    } catch (err) {
      self.postMessage({ type: 'error', message: err.message, _id: id });
    }
    return;
  }
  if (e.data.type === 'history') {
    try {
      self.postMessage({ type: 'history', rows: loadHistory(), _id: id });
    } catch (err) {
      self.postMessage({ type: 'error', message: err.message, _id: id });
    }
    return;
  }
};
