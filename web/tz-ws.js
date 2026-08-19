// tz-ws.js: WebAssembly MTProto Client Driver for Browser

class TzWebClient {
  constructor(options = {}) {
    this.wasmUrl = options.wasmUrl || 'tz.wasm';
    this.apiId = options.apiId || 0;
    this.apiHash = options.apiHash || '';
    this.dcUrl = options.dcUrl || 'wss://venus.web.telegram.org/apiws'; // DC2 Production
    this.onStatus = options.onStatus || console.log;
    this.onLog = options.onLog || console.log;
    this.onQr = options.onQr || console.log;
    this.onLoginSuccess = options.onLoginSuccess || console.log;

    this.wasm = null;
    this.memory = null;
    this.ws = null;
  }

  async init() {
    this.onStatus('Loading WebAssembly module...');
    const textDecoder = new TextDecoder();
    const textEncoder = new TextEncoder();

    const imports = {
      env: {
        js_log: (ptr, len) => {
          const bytes = new Uint8Array(this.memory.buffer, ptr, len);
          this.onLog(`[WASM] ${textDecoder.decode(bytes)}`);
        },
        js_on_status: (ptr, len) => {
          const bytes = new Uint8Array(this.memory.buffer, ptr, len);
          this.onStatus(textDecoder.decode(bytes));
        },
        js_on_qr: (ptr, len) => {
          const bytes = new Uint8Array(this.memory.buffer, ptr, len);
          const qrUrl = textDecoder.decode(bytes);
          this.onQr(qrUrl);
        },
        js_on_login_success: (userId) => {
          this.onLoginSuccess(userId);
        },
        js_ws_send: (ptr, len) => {
          if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            const bytes = new Uint8Array(this.memory.buffer, ptr, len);
            const copy = bytes.slice();
            const hex = Array.from(copy)
              .map(b => b.toString(16).padStart(2, '0')).join(' ');
            this.onLog(`[WS Send] ${copy.length} bytes (hex: ${hex})`);
            this.ws.send(copy.buffer);
          } else {
            this.onLog(`[WS Error] Tried to send ${len} bytes but WS is not open`);
          }
        },
        js_random: (ptr, len) => {
          const buf = new Uint8Array(this.memory.buffer, ptr, len);
          crypto.getRandomValues(buf);
        },
        js_now_sec: () => Math.floor(Date.now() / 1000),
        js_now_ms_part: () => Math.floor(Date.now() % 1000),
      }
    };

    const response = await fetch(this.wasmUrl);
    const wasmBytes = await response.arrayBuffer();
    const module = await WebAssembly.instantiate(wasmBytes, imports);
    this.wasm = module.instance.exports;
    this.memory = this.wasm.memory;

    // Initialize tz client in WASM
    const hashBytes = textEncoder.encode(this.apiHash);
    const hashPtr = this.wasm.tz_alloc(hashBytes.length);
    if (!hashPtr) throw new Error('tz_alloc failed for apiHash');
    new Uint8Array(this.memory.buffer, hashPtr, hashBytes.length).set(hashBytes);

    this.wasm.tz_init(this.apiId, hashPtr, hashBytes.length);
    this.wasm.tz_free(hashPtr, hashBytes.length);
    this.onStatus('WASM ready. Click Connect to start MTProto handshake.');
  }

  setTransportMode(mode) {
    if (this.wasm && this.wasm.tz_set_transport_mode) {
      this.wasm.tz_set_transport_mode(mode);
    }
  }

  setDc(dcUrl) {
    this.dcUrl = dcUrl;
    let dcId = 2;
    if (dcUrl.includes('pluto')) dcId = 1;
    else if (dcUrl.includes('venus')) dcId = 2;
    else if (dcUrl.includes('aurora')) dcId = 3;
    else if (dcUrl.includes('vesta')) dcId = 4;
    else if (dcUrl.includes('flora')) dcId = 5;

    if (dcUrl.includes('_test')) dcId = -dcId;

    if (this.wasm && this.wasm.tz_set_dc_id) {
      this.wasm.tz_set_dc_id(dcId);
    }
  }

  connect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }

    this.onStatus(`Connecting to Telegram DC (${this.dcUrl})...`);
    this.onLog(`[WS] Opening WebSocket connection to ${this.dcUrl}...`);

    this.ws = new WebSocket(this.dcUrl, ['binary']);
    this.ws.binaryType = 'arraybuffer';

    this.ws.onopen = () => {
      this.onLog('[WS] Connection open, triggering WASM DH Handshake...');
      this.wasm.tz_ws_open();
    };

    this.ws.onmessage = (event) => {
      const data = new Uint8Array(event.data);
      const hex = Array.from(data)
        .map(b => b.toString(16).padStart(2, '0')).join(' ');
      this.onLog(`[WS Recv] ${data.byteLength} bytes (hex: ${hex})`);
      
      const ptr = this.wasm.tz_alloc(data.byteLength);
      if (!ptr) {
        this.onLog('[ERROR] WASM OOM on receiving WS frame');
        return;
      }
      try {
        new Uint8Array(this.memory.buffer, ptr, data.byteLength).set(data);
        this.wasm.tz_on_ws_chunk(ptr, data.byteLength);
      } finally {
        this.wasm.tz_free(ptr, data.byteLength);
      }
    };

    this.ws.onerror = (err) => {
      this.onLog(`[WS Error] ${err.message || 'WebSocket Error'}`);
      this.onStatus('WebSocket Error occurred');
    };

    this.ws.onclose = (event) => {
      this.onLog(`[WS Closed] Code: ${event.code}, Reason: ${event.reason || 'None'}`);
      this.onStatus('WebSocket connection closed');
    };
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
      this.onStatus('Disconnected');
      this.onLog('[WS] Disconnected by user');
    }
  }
}
