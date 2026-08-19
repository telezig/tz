# Roadmap: tz — Universal Telegram Client Core

This document outlines the strategic roadmap for evolving `tz` from a lightweight MTProto protocol library into a **universal, zero-dependency Telegram Client Core** capable of powering both high-performance Native CLI/TUI applications and modern Web SDKs (via WebAssembly + OPFS).

---

## 1. Vision & Core Principles

```
                              tz Ecosystem
                       ┌─────────────────────────┐
                       │      @telezig/sdk       │ (Web / Browser / TS)
                       │   CLI / TUI / Daemon    │ (Native Zig / Linux / macOS / Win)
                       │   C-ABI / FFI Bindings  │ (Rust, Swift, Kotlin, Go)
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │     tz Client Engine    │ (Dialogs, Sync, Media, SQLite)
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │   tz MTProto Sans-I/O   │ (Codec, Crypto, Session, Framing)
                       └─────────────────────────┘
```

### Core Architectural Principles
1. **Sans-I/O Core**: The protocol and encryption engines do not perform direct network or filesystem I/O. All platform concerns are injected via a minimal Platform Abstraction Layer (PAL).
2. **Unified Codebase (100% Shared Protocol Logic)**: Handshake, session sequencing, ACK aggregation, container management, and encryption are identical across Native and WebAssembly targets.
3. **Offline-First with SQLite + OPFS**: Local message history, peer caches, and conversation lists reside in SQLite—using native file storage for CLI and synchronous OPFS in Web Workers for browsers.
4. **Zero-Copy & Memory Safety**: Leveraging Zig's memory arenas, explicit allocators, and buffer slicing to achieve minimal overhead (<500KB total WASM bundle).

---

## 2. Research Spikes & Proof-of-Concept (Phase 0)

Before executing broad refactors, validate the riskiest architectural boundaries with minimal prototypes:

- [ ] **POC 1: Zig + SQLite WASM + OPFS vs IndexedDB**
  - **Objective**: Compile `sqlite3.c` directly to `wasm32-freestanding` via Zig's C compiler, wire it to OPFS through a custom VFS, and **decide the Tier-2 message-history storage path by benchmark, not by assumption**.
  - **Motivation**: tz is a core engine; UI/framework cost dominates total bundle size, so size is not the differentiator. The real question is whether sqlite-on-OPFS beats IndexedDB for message history (relational queries, FTS5, batch writes) — and whether its VFS complexity + ~300KB gzip + Safari/Firefox caveats are worth it.
  - **Verification**:
    - Compile + OPFS VFS correctness: 1,000 synchronous batch inserts/queries in a Web Worker via `FileSystemSyncAccessHandle`; **persistence asserted** (close → reopen → count still 1,000).
    - A/B benchmark on the same workload using the real `messages/peers/dialogs` schema: OPFS sqlite vs IndexedDB (batch put, cursor paging, simple filtering). Report throughput and latency for both.
    - Bundle size recorded as gzip (transport size): target core <150KB gzip, sqlite <300KB gzip.
    - Capability detection & fallback: Chrome full OPFS; Safari/Firefox degrade to IndexedDB or memory — no hard dependency.
    - **Output**: a decision note — message history → sqlite (OPFS) or IndexedDB; auth/session KV stays IndexedDB either way (Tier 1), media blobs stay raw OPFS files (Tier 3).
- [ ] **POC 2: Sans-I/O MTProto Engine & Unified Session**
  - **Objective**: Merge `src/mtproto/Session.zig` and `src/wasm.zig` into a single I/O-agnostic `Session` state machine.
  - **Verification**: Run unit tests where both simulated TCP streams and WebSocket buffers drive the exact same session instance without any platform code duplication.
- [ ] **POC 3: TL Schema to TypeScript Type Definition Codegen**
  - **Objective**: Extend `codegen/main.zig` to emit a comprehensive `tl.d.ts` alongside Zig code.
  - **Verification**: Import generated types in TypeScript to verify autocompletion for constructor unions, functions, and flags.

---

## 3. Phased Implementation Roadmap

### Phase 1: Core Decoupling & Sans-I/O Transition
> **Goal**: Make `tz-core` 100% platform-independent and eliminate duplicate MTProto implementations.

- [ ] **1.1 Platform Abstraction Layer (PAL)**
  - Define `Platform` struct: time provider (`now_ms`), CSPRNG (`random`), logger.
  - Native implementation: `std.Io` / `std.posix`.
  - WASM implementation: Web Crypto / `Date.now()`.
- [ ] **1.2 Unified Session & Crypto Pipeline**
  - Unify `mtproto.Session` with integrated time-offset synchronization (`time_offset`), message ID generator (`msg_id`), and sequence number tracking.
  - Abstract framing into a shared transport codec supporting Obfuscated2 (AES-CTR), Intermediate, Padded, and Abridged.
- [ ] **1.3 Automated Update Synchronization & PTS Tracker**
  - Extract PTS/QTS/Date state machine from `client.zig` into a standalone `SyncEngine`.
  - Implement automated gap detection and `updates.getDifference` recovery loop.
- [ ] **1.4 Resilient Peer Cache (Entity Manager)**
  - Intercept RPC responses and incoming updates to auto-populate `InputPeer` cache (`id` -> `access_hash`).
  - Eliminate manual `access_hash` bookkeeping for end users.

### Phase 2: Tiered Storage Engine & Multi-DC Pipeline
> **Goal**: Introduce industrial-grade persistence (SQLite) and transparent multi-DC media transfers.

- [ ] **2.1 Shared Database Layer (`src/db/`)**
  - Embed SQLite (`sqlite3.c`) compiled for both Native and WASM (OPFS).
  - Implement schemas for `sessions`, `peers`, `dialogs`, and `messages`.
  - Enable SQLite FTS5 extension for instant local message search.
- [ ] **2.2 Tiered Storage Architecture**
  - **Tier 1 (Auth State)**: Fast key-value store (Native file / Browser IndexedDB).
  - **Tier 2 (Relational Data)**: SQLite database (Native file / Browser OPFS).
  - **Tier 3 (Media Blobs)**: File system storage (`dc_id/file_id` blobs).
- [ ] **2.3 Multi-DC Connection Pool & Media Worker Engine**
  - Automatic connection routing upon receiving `*_MIGRATE_N` (DC migration).
  - Transparent CDN file download/upload multiplexing across concurrent chunk workers.

### Phase 3: Modern Web SDK (`@telezig/sdk`)
> **Goal**: Provide a first-class, ergonomic TypeScript/JavaScript SDK for browser applications.

- [ ] **3.1 TypeScript Type & Codec Generation**
  - Auto-generate typed interfaces for all TL constructors, requests, and responses (`@telezig/types`).
- [ ] **3.2 Dedicated Web Worker Driver**
  - Package the Zig WASM engine inside a background Web Worker.
  - Zero-copy message passing between Main Thread and Worker.
- [ ] **3.3 Modern High-Level Web API**
  - Promise-based RPC calls: `client.invoke(functions.messages.sendMessage, { ... })`.
  - Reactive Update Streams / EventEmitters: `client.on('message', (msg) => { ... })`.
  - Web Streams API integration: stream file downloads directly to `ReadableStream` / `Blob`.

### Phase 4: High-Performance CLI & Ecosystem Validation
> **Goal**: Deliver a flagship CLI tool and comprehensive end-to-end integration tests.

- [ ] **4.1 Interactive CLI Client**
  - Terminal-based QR login, session switcher, message sender, and live update listener.
  - Optional TUI interface for browsing dialogs and chats.
- [ ] **4.2 Cross-Platform E2E Test Suite**
  - Automated integration test suite running both Native and Headless Browser (Playwright) against Telegram Test DCs.
- [ ] **4.3 Documentation & Migration Guides**
  - Complete API reference, architecture whitepaper, and quick-start guides for Bot, CLI, and Web SDK developers.

---

## 4. Milestone Tracking

| Milestone | Target | Status |
| :--- | :--- | :--- |
| **M0: Feasibility Spikes (POC 1, 2, 3)** | SQLite WASM, Sans-I/O Core, TS Codegen | 🟡 *In Progress* |
| **M1: Unified Core & Sans-I/O Refactor** | Deduplicated Session, PTS Sync, PeerCache | ⚪ *Planned* |
| **M2: SQLite Storage & Multi-DC Pipeline** | SQLite Schema, OPFS VFS, CDN Media Workers | ⚪ *Planned* |
| **M3: TypeScript Web SDK (`@telezig/sdk`)** | Worker Driver, Reactive API, Web Streams | ⚪ *Planned* |
| **M4: Production CLI & E2E Validation** | TUI/CLI Client, Cross-platform Test Suite | ⚪ *Planned* |
