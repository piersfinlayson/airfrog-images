// Airfrog's full user interface, bundled by esbuild 0.28.2 with ci/build-ui.sh.

// js/sha256.js
var K = new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var INITIAL = [
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
];
var W = new Uint32Array(64);
function compress(state, block, at) {
  for (let i = 0; i < 16; i++, at += 4) {
    W[i] = block[at] << 24 | block[at + 1] << 16 | block[at + 2] << 8 | block[at + 3];
  }
  for (let i = 16; i < 64; i++) {
    const a2 = W[i - 15], b2 = W[i - 2];
    const s0 = (a2 >>> 7 | a2 << 25) ^ (a2 >>> 18 | a2 << 14) ^ a2 >>> 3;
    const s1 = (b2 >>> 17 | b2 << 15) ^ (b2 >>> 19 | b2 << 13) ^ b2 >>> 10;
    W[i] = W[i - 16] + s0 + W[i - 7] + s1 | 0;
  }
  let a = state[0], b = state[1], c = state[2], d = state[3];
  let e = state[4], f = state[5], g = state[6], h2 = state[7];
  for (let i = 0; i < 64; i++) {
    const s1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7);
    const t1 = h2 + s1 + (e & f ^ ~e & g) + K[i] + W[i] | 0;
    const s0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10);
    const t2 = s0 + (a & b ^ a & c ^ b & c) | 0;
    h2 = g;
    g = f;
    f = e;
    e = d + t1 | 0;
    d = c;
    c = b;
    b = a;
    a = t1 + t2 | 0;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h2;
}
var Sha256 = class _Sha256 {
  constructor() {
    this.state = new Uint32Array(INITIAL);
    this.buffer = new Uint8Array(64);
    this.buffered = 0;
    this.length = 0;
  }
  clone() {
    const copy = new _Sha256();
    copy.state.set(this.state);
    copy.buffer.set(this.buffer);
    copy.buffered = this.buffered;
    copy.length = this.length;
    return copy;
  }
  /**
   * @param {Uint8Array} data
   * @returns {Sha256}
   */
  update(data) {
    this.length += data.length;
    let at = 0;
    if (this.buffered) {
      const take = Math.min(64 - this.buffered, data.length);
      this.buffer.set(data.subarray(0, take), this.buffered);
      this.buffered += take;
      at = take;
      if (this.buffered < 64) {
        return this;
      }
      compress(this.state, this.buffer, 0);
      this.buffered = 0;
    }
    for (; at + 64 <= data.length; at += 64) {
      compress(this.state, data, at);
    }
    this.buffer.set(data.subarray(at), 0);
    this.buffered = data.length - at;
    return this;
  }
  /**
   * @returns {Uint8Array} 32 bytes
   */
  digest() {
    const bits = this.length * 8;
    const pad = new Uint8Array((this.buffered < 56 ? 56 : 120) - this.buffered + 8);
    pad[0] = 128;
    const view = new DataView(pad.buffer);
    view.setUint32(pad.length - 8, Math.floor(bits / 4294967296));
    view.setUint32(pad.length - 4, bits >>> 0);
    this.update(pad);
    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) {
      outView.setUint32(i * 4, this.state[i]);
    }
    return out;
  }
};
function sha256(data) {
  return new Sha256().update(data).digest();
}
function hmacStart(key) {
  if (key.length > 64) {
    key = sha256(key);
  }
  const block = new Uint8Array(64);
  block.set(key);
  const inner = new Sha256().update(block.map((b) => b ^ 54));
  const outer = new Sha256().update(block.map((b) => b ^ 92));
  return { inner, outer };
}
function hmacSha256(key, ...parts) {
  const { inner, outer } = hmacStart(key);
  for (const part2 of parts) {
    inner.update(part2);
  }
  return outer.update(inner.digest()).digest();
}
function pbkdf2HmacSha256(password, salt, iterations) {
  const { inner, outer } = hmacStart(password);
  const block1 = new Uint8Array([0, 0, 0, 1]);
  let u = outer.clone().update(inner.clone().update(salt).update(block1).digest()).digest();
  const result = u.slice();
  const block = new Uint8Array(64);
  block[32] = 128;
  block[62] = 3;
  const state = new Uint32Array(8);
  for (let i = 1; i < iterations; i++) {
    block.set(u);
    state.set(inner.state);
    compress(state, block, 0);
    for (let j = 0; j < 8; j++) {
      block[j * 4] = state[j] >>> 24;
      block[j * 4 + 1] = state[j] >>> 16;
      block[j * 4 + 2] = state[j] >>> 8;
      block[j * 4 + 3] = state[j];
    }
    state.set(outer.state);
    compress(state, block, 0);
    for (let j = 0; j < 8; j++) {
      u[j * 4] = state[j] >>> 24;
      u[j * 4 + 1] = state[j] >>> 16;
      u[j * 4 + 2] = state[j] >>> 8;
      u[j * 4 + 3] = state[j];
      result[j * 4] ^= u[j * 4];
      result[j * 4 + 1] ^= u[j * 4 + 1];
      result[j * 4 + 2] ^= u[j * 4 + 2];
      result[j * 4 + 3] ^= u[j * 4 + 3];
    }
  }
  return result;
}

// js/schema.js
var SUBPROTOCOL = "airfrog-v1";
var PATH = "/api/ws";
var NONCE_LEN = 16;
var SALT_LEN = 16;
var PROOF_LEN = 32;
var HMAC_LEN = 32;
var LOGIN_LABEL = "login";
var PROOF_LABEL = "airfrog";
var SESSION_LABEL = "session";
var DIRECTION_CLIENT = 0;
var DIRECTION_AIRFROG = 1;
var PIN_NAME_LEN = 8;
var CLAIM_MS = 1e4;
var MAX_TRANSFER_MIN = 4096;
var EXT_IMAGE_MAGIC = "AFXI";
var EXT_NAME_MAX = 32;
var EXT_METADATA_MAX = 2048;
var DOWNLOAD_TIMEOUT_MS = 15e3;
var HELLO = 1;
var LOGIN = 2;
var TARGET = 3;
var ERROR = 4;
var IDENTIFY = 5;
var AIRFROG_CMD = 16;
var CLAIM = 32;
var RELEASE = 33;
var TARGET_CMD = 34;
var EXT_CMD = 48;
var EXT_NOTIFY = 49;
var MESSAGE_TYPES = Object.freeze([
  HELLO,
  LOGIN,
  TARGET,
  ERROR,
  IDENTIFY,
  AIRFROG_CMD,
  CLAIM,
  RELEASE,
  TARGET_CMD,
  EXT_CMD,
  EXT_NOTIFY
]);
function messageTypeName(value) {
  return {
    1: "HELLO",
    2: "LOGIN",
    3: "TARGET",
    4: "ERROR",
    5: "IDENTIFY",
    16: "AIRFROG_CMD",
    32: "CLAIM",
    33: "RELEASE",
    34: "TARGET_CMD",
    48: "EXT_CMD",
    49: "EXT_NOTIFY"
  }[value];
}
var HEADER_RESPONSE = 1;
var ERROR_BUSY = 1;
var ERROR_NOT_CLAIMED = 2;
var ERROR_NOT_OFFERED = 3;
var ERROR_TRANSFER_FAILED = 4;
var ERROR_NOT_RUNNING = 5;
var ERROR_MEMORY_FAULT = 6;
var ERROR_OUT_OF_RANGE = 7;
var ERROR_INSTALL_IN_PROGRESS = 10;
var ERROR_EXTENSION_INVALID = 11;
var ERROR_EXTENSION_UNSUPPORTED = 12;
var ERROR_NO_SPACE = 13;
var ERROR_IMAGE_INVALID = 16;
var ERROR_RESTARTING = 17;
var ERROR_EXISTS = 18;
var CLOSE_PROTOCOL_ERROR = 4e3;
var CLOSE_BAD_COUNTER_OR_HMAC = 4001;
var CLOSE_LOGIN_FAILED = 4002;
var CLOSE_PASSWORD_CHANGED = 4003;
var CLOSE_TOO_MANY_CONNECTIONS = 4004;
var CLOSE_LOGIN_TIMEOUT = 4005;
var CLOSE_NETWORK_SETTINGS_CHANGED = 4006;
var CLOSE_LOGIN_BLOCKED = 4007;
var FLAG_PASSWORD = 1;
var STATE_IDENTIFIED = 1;
var SWD_RESPONDED = 2;
var FW_FLAG_RUNNING = 1;
var Command = Object.freeze({
  GET_HW_INFO: 1,
  GET_FW_INFO: 2,
  GET_WIFI_STA: 3,
  GET_WIFI_AP: 4,
  SET_WIFI_STA: 5,
  SET_PASSWORD: 6,
  GET_HOSTNAME: 7,
  SET_HOSTNAME: 8,
  GET_HOST_ALIASES: 9,
  SET_HOST_ALIASES: 10,
  GET_PIN_MAP: 11,
  GET_SETTINGS: 12,
  SET_SETTINGS: 13,
  OTA_BEGIN: 14,
  OTA_WRITE: 15,
  OTA_FINISH: 16,
  OTA_CONFIRM: 17,
  WIFI_SCAN: 18,
  WIFI_AP_STOP: 19,
  RESTART: 20,
  RESTART_CANCEL: 21,
  GET_BOARDS: 22,
  GET_EXTENSIONS: 23,
  EXT_BEGIN: 24,
  EXT_WRITE: 25,
  EXT_FINISH: 26,
  EXT_REMOVE: 27,
  SET_EXTENSIONS: 28,
  GET_EXTENSION_METADATA: 29,
  GET_AUTHORISED_WEBSITES: 30,
  SET_AUTHORISED_WEBSITES: 31,
  ADD_AUTHORISED_WEBSITE: 32,
  REMOVE_AUTHORISED_WEBSITE: 33,
  ADD_HOST_ALIAS: 34,
  REMOVE_HOST_ALIAS: 35
});
var Firmware = Object.freeze({
  NONE: 0,
  ONE_ROM: 1,
  ONE_ROM_LAB: 2
});
var IdentifyFlag = Object.freeze({
  /** Don't use SWD. */
  NO_SWD: 1,
  /** Don't use a firmware's own protocol, except to check the listed firmware. */
  NO_FIRMWARE_PROTOCOL: 2
});
var IdentifyResult = Object.freeze({
  /** Not checked, because an earlier firmware matched. */
  NOT_CHECKED: 0,
  MATCHED: 1,
  NO_RESPONSE: 2,
  /** A different response. */
  OTHER: 3
});
var StaState = Object.freeze({
  DISABLED: 0,
  CONNECTING: 1,
  CONNECTED: 2,
  FAILED: 3
});
var StaReason = Object.freeze({
  NETWORK_NOT_FOUND: 1,
  WRONG_PASSWORD: 2,
  OTHER: 3
});
var StaFlag = Object.freeze({
  PASSWORD: 1
});
var Ipv4Mode = Object.freeze({
  DHCP: 0,
  STATIC: 1
});
var SetStaFlag = Object.freeze({
  KEEP_PASSWORD: 1
});
var PinRole = Object.freeze({
  NONE: 0,
  RESET: 1,
  BOOT: 2
});
var PinLevel = Object.freeze({
  LOW: 1,
  HIGH: 2
});
var SettingsFlag = Object.freeze({
  RECOVERY: 1,
  WIFI_POWER_SAVE: 2
});
var ScanState = Object.freeze({
  NONE: 0,
  SCANNING: 1,
  DONE: 2,
  FAILED: 3
});
var ScanSecurity = Object.freeze({
  OPEN: 0,
  PASSWORD: 1,
  UNSUPPORTED: 2
});
var RestartMode = Object.freeze({
  GRACEFUL: 0,
  IMMEDIATE: 1
});
var ExtensionFlag = Object.freeze({
  /** The extension's Tab checkbox is ticked. */
  TAB: 1,
  /** Installed from a file, not the repository. */
  SIDE_LOADED: 2
});
var SetExtensionFlag = Object.freeze({
  /** The extension's Tab checkbox is ticked. */
  TAB: 1
});
var WasmState = Object.freeze({
  NO_MODULE: 0,
  RUNNING: 1,
  STOPPED: 2,
  NOT_STARTED: 3
});
var WasmReason = Object.freeze({
  NONE: 0,
  RAN_TOO_LONG: 1,
  CRASHED: 2,
  NOT_ENOUGH_MEMORY: 3,
  /** Built for another WAMR version. */
  OTHER_WAMR_VERSION: 4,
  STOPPED_BY_EXTENSION: 5,
  /** Incompatible with this Airfrog firmware version. */
  INCOMPATIBLE_FIRMWARE: 6,
  /** Recovery boot. */
  RECOVERY_BOOT: 7
});
var Service = Object.freeze({
  RESET: 1,
  SWD_MEMORY: 2,
  PICOBOOT_RP2350_SWD: 3,
  PICOBOOT_ORICP: 4,
  RBCP_ORICP: 5,
  GPIO: 6,
  PICOBOOT_RP2040_SWD: 7
});
var Operation = Object.freeze({
  ALL: 0,
  RESET_RESET: 1,
  RESET_RESET_BOOT: 2,
  RESET_RESET_PINS: 3,
  SWD_MEMORY_READ: 1,
  SWD_MEMORY_WRITE: 2,
  PICOBOOT_RP2350_SWD_COMMAND: 1,
  PICOBOOT_RP2350_SWD_INTERFACE_RESET: 2,
  PICOBOOT_ORICP_COMMAND: 1,
  PICOBOOT_ORICP_INTERFACE_RESET: 2,
  RBCP_ORICP_FRAME: 1,
  GPIO_SET: 1,
  GPIO_GET: 2,
  PICOBOOT_RP2040_SWD_COMMAND: 1,
  PICOBOOT_RP2040_SWD_INTERFACE_RESET: 2
});
var TARGET_MCUS = Object.freeze([
  Object.freeze({ name: "RP2040", designer: 1171, parts: Object.freeze([4098]) }),
  Object.freeze({ name: "RP2350", designer: 1171, parts: Object.freeze([64]) }),
  Object.freeze({ name: "STM32F103", designer: 32, parts: Object.freeze([1040, 1042, 1044, 1072]) }),
  Object.freeze({ name: "STM32F401", designer: 32, parts: Object.freeze([1059, 1075]) }),
  Object.freeze({ name: "STM32F411", designer: 32, parts: Object.freeze([1073]) })
]);
var CHIPS = Object.freeze({
  5: Object.freeze({ name: "ESP32-C3", target: "esp32c3", psram: false }),
  9: Object.freeze({ name: "ESP32-S3", target: "esp32s3", psram: true })
});
var Model = Object.freeze({
  MINI: 1,
  PRO: 2
});
var MODELS = Object.freeze({
  1: Object.freeze({ chip: 5, name: "Mini", key: "mini" }),
  2: Object.freeze({ chip: 9, name: "Pro", key: "pro" })
});
var CLI_TARGETS = Object.freeze({
  "x86_64-pc-windows-msvc": "Windows x86 64-bit",
  "aarch64-pc-windows-msvc": "Windows ARM 64-bit",
  "universal-apple-darwin": "macOS",
  "x86_64-unknown-linux-gnu": "Ubuntu/Debian x86 64-bit",
  "aarch64-unknown-linux-gnu": "Ubuntu/Debian/Pi ARM 64-bit",
  "armv7-unknown-linux-gnueabihf": "Ubuntu/Debian/Pi ARM 32-bit"
});
var TYPE_OFFSET = 0;
var FLAGS_OFFSET = 2;
var COUNTER_OFFSET = 8;
var HMAC_OFFSET = 16;
var HEADER_LEN = 48;
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var FieldReader = class {
  constructor(bytes) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.at = 0;
    this.short = false;
  }
  left() {
    return this.bytes.length - this.at;
  }
  take(n) {
    if (this.short || n > this.left()) {
      this.short = true;
      return null;
    }
    const at = this.at;
    this.at += n;
    return at;
  }
  u8() {
    const at = this.take(1);
    return at === null ? 0 : this.bytes[at];
  }
  i8() {
    const at = this.take(1);
    return at === null ? 0 : this.view.getInt8(at);
  }
  u16() {
    const at = this.take(2);
    return at === null ? 0 : this.view.getUint16(at, true);
  }
  u32() {
    const at = this.take(4);
    return at === null ? 0 : this.view.getUint32(at, true);
  }
  u64() {
    const at = this.take(8);
    return at === null ? 0n : this.view.getBigUint64(at, true);
  }
  bytesOf(n) {
    const at = this.take(n);
    return at === null ? new Uint8Array(0) : this.bytes.slice(at, at + n);
  }
  padded(n) {
    const b = this.bytesOf(n);
    const end = b.indexOf(0);
    return decoder.decode(end < 0 ? b : b.subarray(0, end));
  }
  text() {
    return decoder.decode(this.bytesOf(this.u16()));
  }
  rest() {
    return this.bytesOf(this.left());
  }
  list(count, read) {
    const out = [];
    for (let i = 0; i < count && !this.short; i++) {
      out.push(read());
    }
    return out;
  }
  /** A 2-byte length, then entries of entryLen bytes each. */
  variable(entryLen, read) {
    const n = this.u16();
    if (n % entryLen !== 0) {
      this.short = true;
    }
    return this.list(n / entryLen, read);
  }
};
var FieldWriter = class {
  constructor() {
    this.parts = [];
  }
  number(size, set, value) {
    const b = new Uint8Array(size);
    set(new DataView(b.buffer), value);
    this.parts.push(b);
  }
  u8(v) {
    this.parts.push(new Uint8Array([v ?? 0]));
  }
  i8(v) {
    this.number(1, (d, x) => d.setInt8(0, x), v ?? 0);
  }
  u16(v) {
    this.number(2, (d, x) => d.setUint16(0, x, true), v ?? 0);
  }
  u32(v) {
    this.number(4, (d, x) => d.setUint32(0, x >>> 0, true), v ?? 0);
  }
  u64(v) {
    this.number(8, (d, x) => d.setBigUint64(0, BigInt(x), true), v ?? 0);
  }
  /** n bytes: b, followed by zero bytes. */
  bytesOf(b, n) {
    const out = new Uint8Array(n);
    if (b) {
      if (b.length > n) {
        throw new RangeError(`${b.length} bytes for a ${n}-byte field`);
      }
      out.set(b);
    }
    this.parts.push(out);
  }
  padded(s, n) {
    this.bytesOf(encoder.encode(s ?? ""), n);
  }
  text(s) {
    const b = encoder.encode(s ?? "");
    this.u16(b.length);
    this.parts.push(b);
  }
  raw(b) {
    this.parts.push(b ?? new Uint8Array(0));
  }
  bytes() {
    const out = new Uint8Array(this.parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of this.parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }
};
function readHello(r) {
  const f = {};
  f.revision = r.u16();
  f.flags = r.u16();
  f.maxTransfer = r.u32();
  f.ns = r.bytesOf(16);
  f.salt = r.bytesOf(16);
  f.iterations = r.u32();
  return f;
}
function decodeHello(p) {
  const r = new FieldReader(p);
  const f = readHello(r);
  return r.short ? null : f;
}
function writeLogin(w, f) {
  w.bytesOf(f.nc, 16);
  w.bytesOf(f.proof, 32);
}
function encodeLogin(f) {
  const w = new FieldWriter();
  writeLogin(w, f);
  return w.bytes();
}
function readTarget(r) {
  const f = {};
  f.state = r.u16();
  f.swd = r.u16();
  f.targetid = r.u32();
  f.firmware = r.u32();
  f.fwFlags = r.u16();
  f.services = r.variable(4, () => readServiceEntry(r));
  return f;
}
function decodeTarget(p) {
  const r = new FieldReader(p);
  const f = readTarget(r);
  return r.short ? null : f;
}
function readServiceEntry(r) {
  const f = {};
  f.service = r.u16();
  f.operation = r.u16();
  return f;
}
function writeIdentify(w, f) {
  w.u16(f.flags);
  w.u16(f.count ?? (f.firmware ?? []).length);
  for (const e of f.firmware ?? []) {
    w.u32(e);
  }
}
function encodeIdentify(f) {
  const w = new FieldWriter();
  writeIdentify(w, f);
  return w.bytes();
}
function readIdentifyResponse(r) {
  const f = {};
  f.count = r.u16();
  f.result = r.list(f.count, () => r.u16());
  return f;
}
function decodeIdentifyResponse(p) {
  const r = new FieldReader(p);
  const f = readIdentifyResponse(r);
  return r.short ? null : f;
}
function readError(r) {
  const f = {};
  f.code = r.u16();
  f.detail = r.rest();
  return f;
}
function writeError(w, f) {
  w.u16(f.code);
  w.raw(f.detail);
}
function decodeError(p) {
  const r = new FieldReader(p);
  const f = readError(r);
  return r.short ? null : f;
}
function encodeError(f) {
  const w = new FieldWriter();
  writeError(w, f);
  return w.bytes();
}
function readBusy(r) {
  const f = {};
  f.code = r.u16();
  f.extension = r.text();
  return f;
}
function decodeBusy(p) {
  const r = new FieldReader(p);
  const f = readBusy(r);
  return r.short ? null : f;
}
function readAirfrogCmd(r) {
  const f = {};
  f.command = r.u16();
  f.fields = r.rest();
  return f;
}
function writeAirfrogCmd(w, f) {
  w.u16(f.command);
  w.raw(f.fields);
}
function decodeAirfrogCmd(p) {
  const r = new FieldReader(p);
  const f = readAirfrogCmd(r);
  return r.short ? null : f;
}
function encodeAirfrogCmd(f) {
  const w = new FieldWriter();
  writeAirfrogCmd(w, f);
  return w.bytes();
}
function readHwInfo(r) {
  const f = {};
  f.chip = r.u16();
  f.chipRev = r.bytesOf(2);
  f.flash = r.u32();
  f.psram = r.u32();
  f.mac = r.bytesOf(6);
  f.model = r.u16();
  f.serial = r.left() >= 16 ? r.padded(16) : null;
  return f;
}
function decodeHwInfo(p) {
  const r = new FieldReader(p);
  const f = readHwInfo(r);
  return r.short ? null : f;
}
function readFwInfo(r) {
  const f = {};
  f.version = r.bytesOf(3);
  r.bytesOf(1);
  f.bootloader = r.u16();
  r.bytesOf(2);
  f.wamr = r.bytesOf(3);
  r.bytesOf(1);
  f.commit = r.left() >= 2 ? r.text() : null;
  return f;
}
function decodeFwInfo(p) {
  const r = new FieldReader(p);
  const f = readFwInfo(r);
  return r.short ? null : f;
}
function writeSetPassword(w, f) {
  w.bytesOf(f.key, 32);
  w.bytesOf(f.salt, 16);
}
function encodeSetPassword(f) {
  const w = new FieldWriter();
  writeSetPassword(w, f);
  return w.bytes();
}
function readAuthorisedWebsites(r) {
  const f = {};
  f.count = r.u16();
  f.website = r.list(f.count, () => r.text());
  return f;
}
function decodeAuthorisedWebsites(p) {
  const r = new FieldReader(p);
  const f = readAuthorisedWebsites(r);
  return r.short ? null : f;
}
function writeAuthorisedWebsite(w, f) {
  w.text(f.website);
}
function encodeAuthorisedWebsite(f) {
  const w = new FieldWriter();
  writeAuthorisedWebsite(w, f);
  return w.bytes();
}
function writeOtaWrite(w, f) {
  w.u32(f.offset);
  w.raw(f.data);
}
function encodeOtaWrite(f) {
  const w = new FieldWriter();
  writeOtaWrite(w, f);
  return w.bytes();
}
function readExtImage(r) {
  const f = {};
  f.magic = r.padded(4);
  f.model = r.u16();
  r.bytesOf(2);
  f.wamr = r.bytesOf(3);
  r.bytesOf(1);
  f.metadataOffset = r.u32();
  f.metadataLen = r.u32();
  f.moduleOffset = r.u32();
  f.moduleLen = r.u32();
  f.name = r.text();
  return f;
}
function decodeExtImage(p) {
  const r = new FieldReader(p);
  const f = readExtImage(r);
  return r.short ? null : f;
}
function readExtensions(r) {
  const f = {};
  f.count = r.u16();
  f.entries = r.list(f.count, () => readExtensionEntry(r));
  return f;
}
function decodeExtensions(p) {
  const r = new FieldReader(p);
  const f = readExtensions(r);
  return r.short ? null : f;
}
function readExtensionEntry(r) {
  const f = {};
  f.flags = r.u16();
  f.wasmState = r.u16();
  f.wasmReason = r.u16();
  f.header = readExtImage(r);
  return f;
}
function writeExtBegin(w, f) {
  w.u32(f.size);
  w.bytesOf(f.sha256, 32);
  w.u16(f.flags);
  w.bytesOf(null, 2);
}
function encodeExtBegin(f) {
  const w = new FieldWriter();
  writeExtBegin(w, f);
  return w.bytes();
}
function writeExtensionName(w, f) {
  w.text(f.name);
}
function encodeExtensionName(f) {
  const w = new FieldWriter();
  writeExtensionName(w, f);
  return w.bytes();
}
function writeSetExtensions(w, f) {
  w.u16(f.count ?? (f.entries ?? []).length);
  for (const e of f.entries ?? []) {
    writeSetExtensionsEntry(w, e);
  }
}
function encodeSetExtensions(f) {
  const w = new FieldWriter();
  writeSetExtensions(w, f);
  return w.bytes();
}
function writeSetExtensionsEntry(w, f) {
  w.u16(f.flags);
  w.bytesOf(null, 2);
  w.text(f.name);
}
function writeTargetCmd(w, f) {
  w.u16(f.service);
  w.u16(f.operation);
  w.raw(f.fields);
}
function encodeTargetCmd(f) {
  const w = new FieldWriter();
  writeTargetCmd(w, f);
  return w.bytes();
}
function writeResetPins(w, f) {
  w.padded(f.resetPin, 8);
  w.u16(f.resetLevel);
  w.u16(f.resetMs);
  w.padded(f.bootPin, 8);
  w.u16(f.bootLevel);
  w.u16(f.bootDelayMs);
  w.u16(f.bootHoldMs);
  w.bytesOf(null, 2);
}
function encodeResetPins(f) {
  const w = new FieldWriter();
  writeResetPins(w, f);
  return w.bytes();
}
function readExtCmd(r) {
  const f = {};
  f.name = r.text();
  f.data = r.rest();
  return f;
}
function writeExtCmd(w, f) {
  w.text(f.name);
  w.raw(f.data);
}
function decodeExtCmd(p) {
  const r = new FieldReader(p);
  const f = readExtCmd(r);
  return r.short ? null : f;
}
function encodeExtCmd(f) {
  const w = new FieldWriter();
  writeExtCmd(w, f);
  return w.bytes();
}

// js/target-state.js
var part = (targetid) => targetid >>> 12 & 65535;
function mcuName(targetid) {
  const designer = targetid >>> 1 & 2047;
  return TARGET_MCUS.find((m) => m.designer === designer && m.parts.includes(part(targetid)))?.name ?? null;
}
function firmwareState(target) {
  const name = FIRMWARE[target.firmware]?.name ?? VALUES.FIRMWARE(target.firmware);
  return `${name}: ${target.running() ? RUNNING : STOPPED}`;
}
function targetState(target) {
  if (!target.identified()) {
    return { text: TARGET_STATE.IDENTIFYING, ok: false };
  }
  if (target.firmware) {
    return { text: firmwareState(target), ok: target.running() };
  }
  return { text: target.swd & SWD_RESPONDED ? TARGET_STATE.NO_FIRMWARE : TARGET_STATE.NO_TARGET, ok: false };
}

// js/messages.js
var FIRMWARE = {
  1: { name: "One ROM" },
  2: { name: "One ROM Lab" }
};
var RUNNING = "Running";
var STOPPED = "Stopped";
var SERVICES = {
  1: { name: "RESET", operations: { 1: "RESET", 2: "RESET_BOOT", 3: "RESET_PINS" }, description: "Resets the target using Airfrog's GPIOs." },
  2: { name: "SWD_MEMORY", operations: { 1: "READ", 2: "WRITE" }, description: "SWD access to the target's memory." },
  3: { name: "PICOBOOT_RP2350_SWD", operations: { 1: "COMMAND", 2: "INTERFACE_RESET" } },
  4: { name: "PICOBOOT_ORICP", operations: { 1: "COMMAND", 2: "INTERFACE_RESET" }, description: "Controls the target using PICOBOOT over I2C." },
  5: { name: "RBCP_ORICP", operations: { 1: "FRAME" }, description: "Controls the target using RBCP over I2C." },
  6: { name: "GPIO", operations: { 1: "SET", 2: "GET" }, description: "Controls Airfrog's GPIOs." },
  7: { name: "PICOBOOT_RP2040_SWD", operations: { 1: "COMMAND", 2: "INTERFACE_RESET" } }
};
var TARGET_STATE = {
  IDENTIFYING: "Target: Identifying",
  NO_TARGET: "Target: Not found",
  NO_FIRMWARE: "Target: No firmware found"
};
var RESTARTING = "Airfrog restarting.";
var INVALID_FIRMWARE_FILE = "Invalid firmware file.";
var ERROR_CODES = {
  8: "Internal error.",
  9: "Update already in progress."
};
var CLOSED = {
  PASSWORD_CHANGED: "Password changed.",
  PROTOCOL_ERROR: "Connection closed by Airfrog (unexpected message).",
  BAD_COUNTER_OR_HMAC: "Connection closed by Airfrog (security check failed).",
  TOO_MANY_CONNECTIONS: "Too many connections.",
  LOGIN_TIMEOUT: "Login timed out.",
  NETWORK_SETTINGS_CHANGED: "Network settings changed."
};
var CLOSE_ANOTHER = "Close another page or program using Airfrog";
var RECONNECTING = "Reconnecting\u2026";
var INVALID_VALUE = "Invalid value.";
var ERRORS = {
  TIMEOUT: () => "No response from Airfrog.",
  PASSWORD_REQUIRED: () => "Password required.",
  LOGIN_FAILED: () => "Incorrect password.",
  LOGIN_BLOCKED: (s) => s === 1 ? "Too many failed login attempts. Retry in 1 second." : s === null || s === void 0 ? "Too many failed login attempts. Retry later." : `Too many failed login attempts. Retry in ${s} seconds.`,
  PROOF_MISMATCH: () => "Login failed. Check the Airfrog address.",
  PASSWORD_CHANGED: () => `${CLOSED.PASSWORD_CHANGED} Reconnect with the new password.`,
  PROTOCOL_ERROR: () => `${CLOSED.PROTOCOL_ERROR} Reconnect.`,
  BAD_COUNTER_OR_HMAC: () => `${CLOSED.BAD_COUNTER_OR_HMAC} Reconnect.`,
  TOO_MANY_CONNECTIONS: () => `${CLOSED.TOO_MANY_CONNECTIONS} ${CLOSE_ANOTHER}, then reconnect.`,
  LOGIN_TIMEOUT: () => `${CLOSED.LOGIN_TIMEOUT} Reconnect.`,
  NETWORK_SETTINGS_CHANGED: () => `${CLOSED.NETWORK_SETTINGS_CHANGED} Reconnect.`,
  CLOSED: (code) => !code ? "Connection to Airfrog lost." : `Connection closed by Airfrog (code ${code}).`,
  INVALID_MESSAGE: () => "Unrecognised message from Airfrog.",
  BUSY: (extension) => !extension ? "Target in use. Try again later." : `Target in use by extension "${extension}". Try again later.`,
  NOT_CLAIMED: () => "Target session expired. Try again.",
  NOT_OFFERED: (name) => name === null || name === void 0 ? "Target state changed. Try again." : `Extension ${name} doesn't handle commands.`,
  TRANSFER_FAILED: () => "No response from target.",
  NOT_RUNNING: (name) => name === null || name === void 0 ? "Extension not running." : `Extension ${name} not running.`,
  MEMORY_FAULT: () => "Target memory not readable at that address.",
  OUT_OF_RANGE: () => INVALID_VALUE,
  INSTALL_IN_PROGRESS: () => "Extension install already in progress.",
  EXTENSION_INVALID: () => "Invalid extension.",
  EXTENSION_UNSUPPORTED: () => "Extension not supported by this Airfrog.",
  NO_SPACE: () => "No room for the extension. Remove an extension, then try again.",
  IMAGE_INVALID: () => INVALID_FIRMWARE_FILE,
  RESTARTING: () => RESTARTING,
  CODE: (code) => ERROR_CODES[code] ?? `Airfrog error ${code}.`,
  TRANSFER_TOO_LARGE: (len, max) => `Transfer of ${len} bytes is larger than Airfrog's limit of ${max}`,
  PIN_NAME: (name) => `Pin name ${name} too long. Maximum 8 characters.`,
  CONNECT: () => "Airfrog not found. Check its address and network.",
  IO: () => "Connection to Airfrog failed."
};
var RECONNECT = {
  PASSWORD_CHANGED: `${CLOSED.PASSWORD_CHANGED} ${RECONNECTING}`,
  NETWORK_SETTINGS_CHANGED: `${CLOSED.NETWORK_SETTINGS_CHANGED} ${RECONNECTING}`,
  TOO_MANY_CONNECTIONS: `${CLOSED.TOO_MANY_CONNECTIONS} ${CLOSE_ANOTHER}. ${RECONNECTING}`,
  RESTARTING: `${RESTARTING} ${RECONNECTING}`,
  LOST: `Not connected. ${RECONNECTING}`
};
var CONNECTION = {
  CONNECTING: "Connecting to Airfrog\u2026",
  LOGGING_IN: "Logging in\u2026",
  LOG_IN_AGAIN: `${CLOSED.PASSWORD_CHANGED} Log in again.`,
  /** Followed by a link to the recovery page. */
  FORGOTTEN: "Forgotten password: See ",
  /** The login card's title and button. */
  LOG_IN: "Log in",
  PASSWORD: "Password",
  INVALID_ADDRESS: (host) => `Invalid address ${host}.`,
  NOT_AIRFROG: "Not an Airfrog at this address. Check the address.",
  /** A connection closed by this page, or closed before a command. */
  CLOSED: "Connection to Airfrog closed."
};
var SETTINGS = {
  SAVING: "Saving\u2026",
  SAVED: "Saved.",
  SAVE_FAILED: "Save failed.",
  READ_FAILED: "Settings read failed.",
  /** Airfrog failed a value with OUT_OF_RANGE. */
  INVALID_VALUE,
  SAVE: "Save"
};
var UPDATE = {
  /** The New firmware file tooltip, with the update image's file name. */
  FILE_HELP: (file) => `Airfrog firmware image ${file} from airfrog.org.`,
  INVALID_FILE: INVALID_FIRMWARE_FILE,
  /** Airfrog firmware for another model. */
  WRONG_MODEL: "Invalid firmware file (incorrect Airfrog model).",
  UNSIGNED: "Unsigned firmware.",
  /** The Version row's note. */
  LATEST: "Latest release.",
  /** Followed by why the firmware manifest isn't available. */
  LATEST_UNKNOWN: "Latest release unknown.",
  DOWNLOADING: (version) => `Downloading firmware ${version}\u2026`,
  DOWNLOAD_FAILED: (version, reason) => `Firmware ${version} download failed (${reason}).`,
  /** DOWNLOAD_FAILED's reason when the file doesn't match the firmware manifest. */
  CORRUPT: "file corrupt",
  UPDATING: (version) => `Updating to firmware ${version}\u2026`,
  VERIFYING: "Verifying the firmware\u2026",
  RESTARTING: (version) => `Restarting into firmware ${version}\u2026`,
  RELOADING: "Reloading\u2026",
  UPDATED: (version) => `Updated to firmware ${version}.`,
  REVERTED: (wanted, running) => `Update to firmware ${wanted} failed. Reverted to firmware ${running}.`,
  /** Followed by the reason. */
  FAILED: "Firmware update failed.",
  NO_RESPONSE: (previous) => `No response from Airfrog after restart. Airfrog will revert to firmware ${previous} within 2 minutes.`,
  NOT_CONNECTED: "Not connected to Airfrog.",
  TITLE: "Firmware",
  VERSION_ROW: "Version",
  /** LATEST_UNKNOWN's reason when the firmware manifest isn't valid. */
  INVALID_RELEASE_LIST: "Invalid release list.",
  UPDATE_TO: (version) => `Update to ${version}`,
  RELEASE_NOTES: "Release notes",
  /** DOWNLOAD_FAILED's reason for an HTTP error. */
  HTTP_STATUS: (status) => `HTTP ${status}`,
  /** DOWNLOAD_FAILED's reason when nothing is received for DOWNLOAD_TIMEOUT_MS. */
  TIMED_OUT: "timed out",
  UPDATE_FIRMWARE: "Update firmware",
  FILE: "New firmware file",
  /** The chosen file's mark while it is checked. */
  CHECKING: "Checking",
  VALID: "Valid",
  NOT_VALID: "Not valid",
  /** The button for the chosen file. */
  UPDATE: "Update"
};
var TARGET_CARD = {
  TITLE: "Target",
  CONNECTED: "Connected",
  IDENTIFYING: "Identifying\u2026",
  NO_FIRMWARE: (mcu) => `${mcu}, no firmware found`,
  NO_TARGET: "No target found",
  NO_RESPONSE: "No response from target. Check J1 wiring and target power.",
  RESET: "Reset target",
  RESETTING: "Resetting target\u2026",
  RESET_FAILED: (reason) => `Reset failed. ${reason}`,
  /** The Advanced tab's card's help. */
  TIP: "The board Airfrog is connected to.",
  MCU: "MCU",
  /** The MCU row when the target doesn't respond over SWD. */
  MCU_NO_RESPONSE: "No response",
  FIRMWARE: "Firmware",
  BOARD: "Board",
  /** The Board row's link to the board type setting. */
  CHANGE: "Change",
  SERVICES: "Services",
  SERVICES_TIP: "Services clients can use on this target through Airfrog."
};
var PINS = {
  TITLE: "Airfrog pins",
  TIP: "J1 and J2 pinout for the connected target.",
  /** The board render's aria-label. */
  BOARD: (model) => `Airfrog ${model} with J1 and J2 labelled`,
  /** A connector drawing's aria-label. */
  CONNECTOR: (connector) => `${connector} pins`,
  PIN: "Pin",
  NAME: "Name"
};
var AIRFROG = "Airfrog";
var PAGE = {
  /** The header's firmware version. */
  FIRMWARE: (version) => `firmware ${version}`,
  /** The header's Airfrog model. */
  MODEL: (model) => `${AIRFROG} ${model}`,
  NETWORK_TAB: "Network",
  SYSTEM_TAB: "System",
  ADVANCED_TAB: "Advanced",
  /** The Target tab's name. */
  TARGET_TAB: "Target",
  FOOTER_VERSION: (version) => `${AIRFROG} ${version}`,
  /** Before the author's link in the footer. */
  FROM: "from"
};
var VALUES = {
  /** A value Airfrog doesn't have or that doesn't apply. */
  NONE: "-",
  /** A board not in GET_BOARDS's list, by its ID in hex. */
  BOARD: (id) => `Board 0x${id}`,
  /** Firmware Airfrog doesn't recognise, by its ID. */
  FIRMWARE: (id) => `Firmware ${id}`,
  /** An MCU this page doesn't recognise, by GET_HW_INFO's chip. */
  MCU: (chip) => `MCU ${chip}`,
  /** A model without a name in this code, by its number. */
  MODEL: (number) => `Model ${number}`,
  MCU_REVISION: (mcu, revision) => `${mcu}, revision ${revision}`,
  /** A target MCU Airfrog's rules don't include, by its TARGETID in hex. */
  TARGET_MCU: (id) => `Unknown MCU (ID 0x${id})`,
  /** A value that can't be read or isn't recognised. */
  UNKNOWN: "Unknown",
  /** A service not in SERVICES, by its number. */
  SERVICE: (service) => `Service ${service}`,
  /** An operation not in SERVICES, by its number. */
  OPERATION: (operation) => `operation ${operation}`,
  VERSION: (version) => `v${version}`,
  WITH_COMMIT: (version, commit) => `${version} (${commit})`,
  MB: (size) => `${size} MB`,
  KB: (size) => `${size} KB`,
  DBM: (rssi) => `${rssi} dBm`
};
var CONTROLS = {
  /** A prompt's button that closes it. */
  CANCEL: "Cancel",
  CHOOSE_FILE: "Choose file"
};
var UNRECOGNISED_REPLY = "Unrecognised reply from Airfrog. Firmware may be newer than this page.";
var EXTENSIONS = {
  /** The tab's name. */
  TAB: "Extensions",
  INSTALLED_TITLE: "Extensions",
  NONE_INSTALLED: "No extensions installed.",
  /** The installed list's column headers. */
  EXTENSION: "Extension",
  VERSION: "Version",
  STATE: "State",
  TAB_COLUMN: "Tab",
  /** The Tab checkbox's label for screen readers. */
  TAB_CHECKBOX: (name) => `${name} tab`,
  /** After the installed version. */
  LATEST: (version) => `latest ${version}`,
  SIDE_LOADED: "from file",
  DEPUBLISHED: "Depublished",
  RUNNING,
  STOPPED,
  UI_ONLY: "UI only",
  OPEN: "Open",
  UPDATE: "Update",
  REINSTALL: "Reinstall",
  REMOVE: "Remove",
  INSTALL: "Install",
  DRAG_NOTE: "Drag to reorder. Tabs appear in this order.",
  /** The button and its view's title. */
  ADD: "Install extensions",
  FROM_FILE: "Install from file",
  BACK: "Back",
  SEARCH: "Search",
  FOR: "For:",
  ANY_TARGET: "Any target",
  OTHER_TARGETS: "Other targets",
  COUNT: (shown, total) => `${shown} of ${total} available extensions`,
  SIDE_LOAD_CONFIRM: "Extensions added from a file have full access to Airfrog.",
  REMOVE_CONFIRM: (name) => `Are you sure you want to remove ${name}?`,
  INSTALLING: (name, version) => `Installing ${name} ${version}\u2026`,
  INSTALLED: (name, version) => `Installed ${name} ${version}.`,
  UPDATING: (name, version) => `Updating ${name} to ${version}\u2026`,
  UPDATED: (name, version) => `Updated ${name} to ${version}.`,
  REMOVING: (name) => `Removing ${name}\u2026`,
  REMOVED: (name) => `Removed ${name}.`,
  /** Followed by the reason. */
  INSTALL_FAILED: "Install failed.",
  /** Followed by the reason. */
  UPDATE_FAILED: "Update failed.",
  /** Followed by the reason. */
  REMOVE_FAILED: "Remove failed.",
  /** Followed by the reason. */
  READ_FAILED: "Extensions read failed.",
  /** Followed by the reason. */
  LIST_NOT_LOADED: "Extension list not loaded.",
  INVALID_FILE: "Invalid extension file.",
  /** A downloaded extension image that doesn't match the extension list. */
  CORRUPT: "Download corrupt. Try again.",
  /** EXT_CMD's OUT_OF_RANGE. */
  NOT_INSTALLED: (name) => `Extension ${name} not installed.`,
  LOADING_UI: (name) => `Loading ${name} UI\u2026`,
  UI_FAILED: (name) => `${name} UI failed to load. Reload the page.`,
  /** connectExtension() in a page that isn't inside the Airfrog UI. */
  NOT_IN_AIRFROG_UI: "Not inside the Airfrog UI.",
  /** A request an extension UI can't send, by its name. */
  NOT_PERMITTED: (name) => `${name} not available to an extension UI.`
};
var RELEASE_LIST = {
  SIGNATURE: "Release list signature invalid.",
  INVALID: UPDATE.INVALID_RELEASE_LIST
};
var HOME_PAGE = {
  TITLE: AIRFROG,
  LOADING: "Loading\u2026",
  DOWNLOAD_FAILED: "Download failed. Check internet access.",
  DOWNLOAD_HTTP: (status) => `Download failed (HTTP ${status}).`,
  DOWNLOAD_TIMED_OUT: "Download failed (timed out).",
  RELEASE_LIST_SIGNATURE: RELEASE_LIST.SIGNATURE,
  RELEASE_LIST_INVALID: RELEASE_LIST.INVALID,
  MANIFEST_SIGNATURE: "Invalid signature.",
  MANIFEST_INVALID: "Invalid manifest.",
  NO_MANIFEST_KEY: "Rebuild firmware with CONFIG_AIRFROG_MANIFEST_KEY.",
  NEWER_FIRMWARE: "Newer firmware required. Update firmware.",
  DOWNLOAD_CORRUPT: "Download corrupt. Reload the page.",
  INCOMPLETE: "Incomplete release.",
  START_FAILED: "Start failed. Reload the page.",
  BRIDGE_NOT_LOADED: (reason) => `Bridge window not loaded. ${reason}`,
  UI_FAILED: "Airfrog UI failed to load. Reload the page."
};
var BRIDGE = {
  /** The browser tab title. */
  TITLE: (host, site) => `${host} (${site})`,
  /** Before connecting a website that isn't authorised. */
  ALLOW_CONNECT: (site, host) => `Allow ${site} to connect to ${host}?`,
  ALLOW: "Allow",
  OPENED_DIRECTLY: "Do not open this window directly.",
  CONNECT_FROM: (site) => `Close this window and connect from ${site}.`,
  ENTER_PASSWORD: (host, site) => `Enter ${host}'s password to allow ${site} to connect.`,
  /** Followed by a link to the recovery page. */
  FORGOTTEN: "Forgotten password:",
  CONNECTED: (site, host) => `${site} is connected to ${host}.`,
  CLOSING_DISCONNECTS: (site, host) => `Closing this window disconnects ${site} from ${host}.`,
  DISCONNECT: "Disconnect",
  DISCONNECTED: (site, host) => `${site} was disconnected from ${host}.`,
  NOT_CONNECTED: (site, host) => `${site} couldn't connect to ${host}.`,
  RECONNECT_FROM: (site) => `Reconnect from ${site}.`,
  CLOSE: "Close",
  PASSWORD_CHANGED: (host) => `${host}'s password was changed.`,
  RESTARTED: (host) => `${host} restarted.`,
  NOT_RESPONDING: (host) => `${host} stopped responding.`,
  NETWORK_SETTINGS_CHANGED: (host) => `${host}'s network settings were changed.`,
  PROTOCOL_ERROR: (host, site) => `${host} received an unexpected message from ${site}.`,
  BAD_COUNTER_OR_HMAC: (host) => `${host} received a message with an invalid signature or sequence number.`,
  UNKNOWN_CLOSE: (host, code) => `${host} closed the connection with unknown error ${code}.`,
  TOO_MANY_CONNECTIONS: (host) => `${host} has too many connections. Close another page or program connected to ${host}.`,
  LOGIN_TIMEOUT: (host) => `${host} closed the connection because the login timed out.`,
  TOO_MANY_WEBSITES: (host) => `${host} has too many authorised websites. Revoke one in ${host}'s System tab.`,
  ADD_FAILED: (site, host) => `Failed to add ${site} as an authorised website on ${host}.`,
  REVOKED: (site) => `${site}'s authorisation has been revoked.`,
  READ_FAILED: (host) => `Failed to read ${host}'s authorised websites.`,
  PROOF_MISMATCH: (host) => `${host} sent an invalid response to the login.`,
  INVALID_FROM_AIRFROG: (host) => `Received an unexpected message from ${host}.`,
  INVALID_FROM_SITE: (site) => `Received a message from ${site} with an invalid type or payload.`,
  /** With the message's name, and an AIRFROG_CMD's command. */
  UNSUPPORTED_FROM_SITE: (name, site) => `Received an unsupported message (${name}) from ${site}.`,
  WINDOW_CLOSED: (host) => `The ${host} window was closed.`,
  WINDOW_DISCONNECTED: (host) => `The ${host} window ended the connection.`,
  BLOCKED: (host, site) => `Connecting to ${host} opens a pop-up window which the browser blocked. Allow pop-ups for ${site}, then retry.`
};
var COMMISSIONING_FIRMWARE = {
  RELEASE: "Release",
  INSTALL_FIRMWARE: "Install firmware",
  INSTALL_TIP: "Erases the Airfrog flash, settings included, and writes the release.",
  KEEP: "Keep current firmware",
  KEEP_TIP: "Starts the current Airfrog firmware and keeps the settings.",
  CONFIRM_INSTALL: (version) => `Install firmware ${version}? The Airfrog settings are erased.`,
  /** CONFIRM_INSTALL's button. */
  INSTALL: "Install",
  MANIFEST_KEY_NOT_SET: "Manifest key not set.",
  /** A download's name. */
  RELEASE_LIST: "Release list",
  /** A download's name. */
  FIRMWARE: "Firmware",
  /** A download's name. */
  RELEASE_VERSION: (version) => `Release v${version}`,
  DOWNLOAD_FAILED: (download2) => `${download2} download failed. Check internet access.`,
  DOWNLOAD_HTTP: (download2, status) => `${download2} download failed (HTTP ${status}).`,
  DOWNLOAD_TIMED_OUT: (download2) => `${download2} download failed (timed out).`,
  DOWNLOAD_CORRUPT: (download2) => `${download2} download corrupt.`,
  FLASH_SIZE_DIFFERS: "Release flash size doesn't match the Airfrog flash size.",
  RELEASE_LIST_NOT_LOADED: "Release list not loaded.",
  RELOAD: "Reload the page to try again.",
  /** No released model has the connected board's MCU and PSRAM. */
  NOT_RECOGNISED: "Airfrog model not recognised.",
  NO_RELEASES: (model) => `No ${model} firmware released.`,
  /** Keep current firmware. Both are model names. */
  WRONG_FIRMWARE: (installed, model) => `Airfrog firmware is for ${installed}, not ${model}.`,
  /**
   * Install firmware or Keep current firmware connected again, to a board
   * the selected model doesn't run on. Model lists the new board's models.
   */
  BOARD_CHANGED: "Airfrog board changed. Check the model.",
  /** Keep current firmware. The board's flash is blank or the firmware can't be read. */
  FIRMWARE_NOT_FOUND: "Airfrog firmware not found.",
  ERASING: "Erasing Airfrog flash\u2026",
  INSTALLING: (version) => `Installing firmware ${version}\u2026`,
  /** With esptool-js's error. */
  WRITE_FAILED: (reason) => `Firmware write failed. ${reason}`,
  CONNECT_TO_RESTART: "Select Connect to start again.",
  INSTALL_TO_RETRY: "Select Install firmware to try again, or choose another release.",
  STARTING: "Starting Airfrog\u2026",
  NOT_RELEASED: (version) => `Firmware ${version} not a published release.`,
  SELECT_INSTALL: "Select Install firmware.",
  NOT_SUPPORTED: (release) => `Release ${release} not supported by this page.`,
  READING_SETTINGS: "Reading Airfrog settings\u2026",
  KEEP_TO_RETRY: "Select Keep current firmware to try again.",
  NO_SERIAL_RESPONSE: "No response from Airfrog over serial.",
  CHECK_TX: "Check adapter TX to J2 RX, then select Keep current firmware.",
  SERIAL_FAILED: (reason) => `Serial port failed. ${reason}`,
  CHECK_ADAPTER: "Check the adapter is plugged in, then select Connect."
};

// js/awp.js
var KNOWN = new Set(MESSAGE_TYPES);
function isKnown(type) {
  return KNOWN.has(type);
}
function typeName(type) {
  return messageTypeName(type) ?? hex(type);
}
var CONNECT_TIMEOUT_MS = 5e3;
var FROM_CLIENT = new Uint8Array([DIRECTION_CLIENT]);
var FROM_AIRFROG = new Uint8Array([DIRECTION_AIRFROG]);
var ASCII = new TextEncoder();
function hex(type) {
  return `0x${type.toString(16).padStart(4, "0")}`;
}
var AirfrogError = class extends Error {
  /**
   * @param {string} code
   * @param {*} [detail]
   * @param {string} [message] - in place of the code's own
   */
  constructor(code, detail = null, message2 = void 0) {
    super(message2 ?? ERRORS[code]?.(detail) ?? code);
    this.name = "AirfrogError";
    this.code = code;
    this.detail = detail;
  }
};
function errorFromClose(code, reason) {
  switch (code) {
    case CLOSE_LOGIN_BLOCKED: {
      const seconds = /^\s*\d+\s*$/.test(reason ?? "") ? Number(reason) : null;
      return new AirfrogError("LOGIN_BLOCKED", seconds);
    }
    case CLOSE_PROTOCOL_ERROR:
      return new AirfrogError("PROTOCOL_ERROR");
    case CLOSE_BAD_COUNTER_OR_HMAC:
      return new AirfrogError("BAD_COUNTER_OR_HMAC");
    case CLOSE_LOGIN_FAILED:
      return new AirfrogError("LOGIN_FAILED");
    case CLOSE_PASSWORD_CHANGED:
      return new AirfrogError("PASSWORD_CHANGED");
    case CLOSE_TOO_MANY_CONNECTIONS:
      return new AirfrogError("TOO_MANY_CONNECTIONS");
    case CLOSE_LOGIN_TIMEOUT:
      return new AirfrogError("LOGIN_TIMEOUT");
    case CLOSE_NETWORK_SETTINGS_CHANGED:
      return new AirfrogError("NETWORK_SETTINGS_CHANGED");
    // A browser reports 1005 for a close frame without a code and 1006
    // for a connection lost without one.
    case 1005:
    case 1006:
      return new AirfrogError("CLOSED", null);
    default:
      return new AirfrogError("CLOSED", code);
  }
}
var ERROR_CODES2 = {
  [ERROR_BUSY]: "BUSY",
  [ERROR_NOT_CLAIMED]: "NOT_CLAIMED",
  [ERROR_NOT_OFFERED]: "NOT_OFFERED",
  [ERROR_TRANSFER_FAILED]: "TRANSFER_FAILED",
  [ERROR_NOT_RUNNING]: "NOT_RUNNING",
  [ERROR_MEMORY_FAULT]: "MEMORY_FAULT",
  [ERROR_OUT_OF_RANGE]: "OUT_OF_RANGE",
  [ERROR_INSTALL_IN_PROGRESS]: "INSTALL_IN_PROGRESS",
  [ERROR_EXTENSION_INVALID]: "EXTENSION_INVALID",
  [ERROR_EXTENSION_UNSUPPORTED]: "EXTENSION_UNSUPPORTED",
  [ERROR_NO_SPACE]: "NO_SPACE",
  [ERROR_IMAGE_INVALID]: "IMAGE_INVALID",
  [ERROR_RESTARTING]: "RESTARTING"
};
function errorFromPayload(payload) {
  const error = decodeError(payload);
  if (!error) {
    return null;
  }
  const name = ERROR_CODES2[error.code];
  if (error.code === ERROR_BUSY) {
    const busy = decodeBusy(payload);
    return busy ? new AirfrogError(name, busy.extension) : null;
  }
  return name ? new AirfrogError(name) : new AirfrogError("CODE", error.code);
}
function viewOf(bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}
var TargetInfo = class _TargetInfo {
  constructor() {
    this.state = 0;
    this.swd = 0;
    this.targetid = 0;
    this.firmware = 0;
    this.fwFlags = 0;
    this.services = [];
  }
  /**
   * @param {Uint8Array} p - TARGET's payload
   * @returns {TargetInfo|null} null for a payload too short for its fields.
   *          Bytes from a later revision are ignored
   */
  static parse(p) {
    const f = decodeTarget(p);
    if (!f) {
      return null;
    }
    const t = new _TargetInfo();
    t.state = f.state;
    t.swd = f.swd;
    t.targetid = f.targetid;
    t.firmware = f.firmware;
    t.fwFlags = f.fwFlags;
    t.services = f.services;
    return t;
  }
  /** @returns {boolean} whether identification is complete */
  identified() {
    return this.state === STATE_IDENTIFIED;
  }
  /** @returns {boolean} whether Airfrog has confirmed the firmware is running */
  running() {
    return (this.fwFlags & FW_FLAG_RUNNING) !== 0;
  }
  /**
   * @param {number} service
   * @returns {boolean} whether any operation of service is supported
   */
  offers(service) {
    return this.services.some((s) => s.service === service);
  }
  /**
   * @param {number} service
   * @param {number} operation
   * @returns {boolean} whether operation of service is supported
   */
  supports(service, operation) {
    return this.services.some((s) => s.service === service && (s.operation === 0 || s.operation === operation));
  }
};
var Hello = class _Hello {
  /**
   * @param {Uint8Array} p
   * @returns {Hello|null}
   */
  static parse(p) {
    const f = decodeHello(p);
    return f ? Object.assign(new _Hello(), f) : null;
  }
  hasPassword() {
    return (this.flags & FLAG_PASSWORD) !== 0;
  }
};
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}
function passwordKey(password, salt, iterations) {
  return pbkdf2HmacSha256(ASCII.encode(password), salt, iterations);
}
function equal(a, b) {
  let diff = a.length ^ b.length;
  for (let i = 0; i < a.length && i < b.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
var AwpSocket = class _AwpSocket {
  /**
   * Opens the connection, reads HELLO and logs in where Airfrog has a
   * password.
   * @param {string} host - Airfrog's host, with :port when it isn't 80
   * @param {string|null} password - ignored when Airfrog doesn't have one
   * @returns {Promise<AwpSocket>}
   */
  static open(host, password) {
    return new Promise((resolve, reject) => {
      let ws;
      try {
        ws = new WebSocket(`ws://${host}${PATH}`, SUBPROTOCOL);
      } catch (e) {
        reject(new AirfrogError("CONNECT", `invalid host ${host}`, CONNECTION.INVALID_ADDRESS(host)));
        return;
      }
      new _AwpSocket(ws, password, resolve, reject);
    });
  }
  constructor(ws, password, resolve, reject) {
    this.ws = ws;
    this.tx = 0;
    this.rx = 0;
    this.key = null;
    this.hello = null;
    this.helloPayload = null;
    this.closed = null;
    this.held = [];
    this._onmessage = null;
    this.onclose = null;
    this.password = password;
    this.opening = { resolve, reject, timer: setTimeout(() => this.fail(new AirfrogError("TIMEOUT")), CONNECT_TIMEOUT_MS) };
    this.nc = null;
    this.k = null;
    ws.binaryType = "arraybuffer";
    this.wsOpen = false;
    ws.onopen = () => {
      this.wsOpen = true;
      if (ws.protocol !== SUBPROTOCOL) {
        this.fail(new AirfrogError(
          "CONNECT",
          `subprotocol ${SUBPROTOCOL} not selected`,
          CONNECTION.NOT_AIRFROG
        ));
      }
    };
    ws.onmessage = (event) => this.receive(event.data);
    ws.onclose = (event) => {
      const error = this.wsOpen ? errorFromClose(event.code, event.reason) : new AirfrogError("CONNECT", "the WebSocket failed to open");
      this.ended(error);
    };
    ws.onerror = () => {
    };
  }
  set onmessage(handler) {
    this._onmessage = handler;
    const held = this.held;
    this.held = [];
    for (const [type, flags, payload] of held) {
      handler(type, flags, payload);
    }
  }
  get onmessage() {
    return this._onmessage;
  }
  opened() {
    return this.opening === null;
  }
  /**
   * Sends a message with the next counter, signed once logged in.
   * @param {number} type
   * @param {Uint8Array} payload
   */
  send(type, payload) {
    if (this.closed) {
      throw this.closed;
    }
    this.tx += 1;
    const header = new Uint8Array(HMAC_OFFSET);
    const view = viewOf(header);
    view.setUint16(TYPE_OFFSET, type, true);
    view.setBigUint64(COUNTER_OFFSET, BigInt(this.tx), true);
    const mac = this.key ? hmacSha256(this.key, FROM_CLIENT, header, payload) : new Uint8Array(HMAC_LEN);
    try {
      this.ws.send(concat(header, mac, payload));
    } catch (e) {
      const error = new AirfrogError("IO", e.message);
      console.debug(`Sending to Airfrog failed: ${e.message}`);
      this.fail(error);
      throw error;
    }
  }
  /**
   * Closes the connection. Nothing more is delivered.
   * @param {number} [code] - the close code, for example 4000
   * @param {AirfrogError} [error] - the reason recorded, CLOSED by default
   */
  close(code, error) {
    this.fail(error ?? new AirfrogError("CLOSED", null, CONNECTION.CLOSED), code);
  }
  /**
   * Closes the connection with code, if it is open, and records error as
   * the reason.
   */
  fail(error, code) {
    if (this.closed) {
      return;
    }
    console.debug(`Closing the connection to Airfrog: ${error.code} ${error.detail ?? ""}`);
    try {
      if (code) {
        this.ws.close(code);
      } else {
        this.ws.close();
      }
    } catch (e) {
    }
    this.ended(error);
  }
  ended(error) {
    if (this.closed) {
      return;
    }
    this.closed = error;
    if (this.opening) {
      clearTimeout(this.opening.timer);
      this.opening.reject(error);
      this.opening = null;
      return;
    }
    this.onclose?.(error);
  }
  receive(data) {
    if (this.closed) {
      return;
    }
    if (!(data instanceof ArrayBuffer)) {
      this.fail(new AirfrogError("INVALID_MESSAGE", "text message"), CLOSE_PROTOCOL_ERROR);
      return;
    }
    const bytes = new Uint8Array(data);
    if (bytes.length < HEADER_LEN) {
      this.fail(new AirfrogError("INVALID_MESSAGE", `${bytes.length}-byte message`), CLOSE_PROTOCOL_ERROR);
      return;
    }
    const view = viewOf(bytes);
    const type = view.getUint16(TYPE_OFFSET, true);
    const flags = view.getUint16(FLAGS_OFFSET, true);
    const counter = Number(view.getBigUint64(COUNTER_OFFSET, true));
    if (counter !== this.rx + 1) {
      this.fail(new AirfrogError("INVALID_MESSAGE", `counter ${counter} after ${this.rx}`), CLOSE_BAD_COUNTER_OR_HMAC);
      return;
    }
    const payload = bytes.slice(HEADER_LEN);
    if (this.key && !equal(
      hmacSha256(this.key, FROM_AIRFROG, bytes.subarray(0, HMAC_OFFSET), payload),
      bytes.subarray(HMAC_OFFSET, HEADER_LEN)
    )) {
      this.fail(new AirfrogError("INVALID_MESSAGE", `bad hmac on ${hex(type)} #${counter}`), CLOSE_BAD_COUNTER_OR_HMAC);
      return;
    }
    this.rx = counter;
    if (!this.opened()) {
      this.login(type, flags, payload);
    } else if (this._onmessage) {
      this._onmessage(type, flags, payload);
    } else {
      this.held.push([type, flags, payload]);
    }
  }
  login(type, flags, payload) {
    if (!this.hello) {
      if (type !== HELLO) {
        this.fail(new AirfrogError("INVALID_MESSAGE", `${hex(type)} before HELLO`), CLOSE_PROTOCOL_ERROR);
        return;
      }
      const hello = Hello.parse(payload);
      if (!hello) {
        this.fail(new AirfrogError("INVALID_MESSAGE", `${payload.length}-byte HELLO`), CLOSE_PROTOCOL_ERROR);
        return;
      }
      if (hello.revision < 1) {
        this.fail(new AirfrogError("INVALID_MESSAGE", `AWP revision ${hello.revision}`), CLOSE_PROTOCOL_ERROR);
        return;
      }
      this.hello = hello;
      this.helloPayload = payload;
      if (!hello.hasPassword()) {
        this.loggedIn();
        return;
      }
      if (this.password === null || this.password === void 0) {
        this.fail(new AirfrogError("PASSWORD_REQUIRED"));
        return;
      }
      if (hello.iterations === 0) {
        this.fail(new AirfrogError("INVALID_MESSAGE", "HELLO has a password and zero iterations"), CLOSE_PROTOCOL_ERROR);
        return;
      }
      this.k = passwordKey(this.password, hello.salt, hello.iterations);
      this.nc = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
      const proof = hmacSha256(this.k, ASCII.encode(LOGIN_LABEL), hello.ns, this.nc);
      this.send(LOGIN, encodeLogin({ nc: this.nc, proof }));
      return;
    }
    if (!isKnown(type)) {
      return;
    }
    if (type !== LOGIN || !(flags & HEADER_RESPONSE)) {
      this.fail(new AirfrogError("INVALID_MESSAGE", `${hex(type)} in response to ${hex(LOGIN)}`), CLOSE_PROTOCOL_ERROR);
      return;
    }
    if (payload.length < PROOF_LEN) {
      this.fail(new AirfrogError("INVALID_MESSAGE", `${payload.length}-byte LOGIN response`), CLOSE_PROTOCOL_ERROR);
      return;
    }
    const ns = this.hello.ns;
    if (!equal(hmacSha256(this.k, ASCII.encode(PROOF_LABEL), ns, this.nc), payload.subarray(0, PROOF_LEN))) {
      this.fail(new AirfrogError("PROOF_MISMATCH"));
      return;
    }
    this.key = hmacSha256(this.k, ASCII.encode(SESSION_LABEL), ns, this.nc);
    this.loggedIn();
  }
  loggedIn() {
    this.password = null;
    this.k = null;
    const { resolve, timer } = this.opening;
    clearTimeout(timer);
    this.opening = null;
    resolve(this);
  }
};
var BRIDGE_KEY = "airfrogBridge";
var EXTENSION_KEY = "airfrogExtension";
function siteName(origin) {
  return origin.startsWith("https://") ? new URL(origin).host : origin;
}
function errorToBridge(e) {
  return { code: e.code ?? "CLOSED", detail: e.detail ?? null, message: e.message };
}
function errorFromBridge(close) {
  const code = typeof close?.code === "string" ? close.code : "CLOSED";
  const message2 = typeof close?.message === "string" ? close.message : void 0;
  return new AirfrogError(code, close?.detail ?? null, message2);
}

// js/urls.js
var AIRFROG_TLD = "https://airfrog.org/";
var RECOVERY = "https://airfrog.org/recovery";

// js/bridge.js
var CHECK_MS = 10 * 60 * 1e3;
var OPENER_POLL_MS = 500;
var FORWARDED = /* @__PURE__ */ new Set([CLAIM, RELEASE, TARGET_CMD, IDENTIFY]);
function bridgeOrigin(hash) {
  const match = /^#bridge=(.+)$/.exec(hash);
  if (!match) {
    return null;
  }
  try {
    const origin = decodeURIComponent(match[1]);
    const url = new URL(origin);
    return ["http:", "https:"].includes(url.protocol) && url.origin === origin ? origin : null;
  } catch (e) {
    return null;
  }
}
function refusal({ type, payload }, site) {
  if (!Number.isInteger(type) || type < 0 || type > 65535 || !(payload instanceof Uint8Array)) {
    return BRIDGE.INVALID_FROM_SITE(site);
  }
  if (FORWARDED.has(type)) {
    return null;
  }
  if (type === AIRFROG_CMD) {
    const cmd = decodeAirfrogCmd(payload);
    if (!cmd) {
      return BRIDGE.INVALID_FROM_SITE(site);
    }
    const name = Object.keys(Command).find((k) => Command[k] === cmd.command);
    return name?.startsWith("GET_") ? null : BRIDGE.UNSUPPORTED_FROM_SITE(`AIRFROG_CMD ${name ?? hex(cmd.command)}`, site);
  }
  return BRIDGE.UNSUPPORTED_FROM_SITE(typeName(type), site);
}
function reasonFor(e, host, site) {
  switch (e.code) {
    case "PASSWORD_CHANGED":
      return BRIDGE.PASSWORD_CHANGED(host);
    case "NETWORK_SETTINGS_CHANGED":
      return BRIDGE.NETWORK_SETTINGS_CHANGED(host);
    case "PROTOCOL_ERROR":
      return BRIDGE.PROTOCOL_ERROR(host, site);
    case "BAD_COUNTER_OR_HMAC":
      return BRIDGE.BAD_COUNTER_OR_HMAC(host);
    case "TOO_MANY_CONNECTIONS":
      return BRIDGE.TOO_MANY_CONNECTIONS(host);
    case "LOGIN_TIMEOUT":
      return BRIDGE.LOGIN_TIMEOUT(host);
    case "PROOF_MISMATCH":
      return BRIDGE.PROOF_MISMATCH(host);
    case "INVALID_MESSAGE":
      return BRIDGE.INVALID_FROM_AIRFROG(host);
    case "CONNECT":
    case "IO":
    case "TIMEOUT":
      return BRIDGE.NOT_RESPONDING(host);
    case "CLOSED":
      if (e.detail === null) {
        return BRIDGE.NOT_RESPONDING(host);
      }
      return e.detail === 1001 ? BRIDGE.RESTARTED(host) : BRIDGE.UNKNOWN_CLOSE(host, e.detail);
    default:
      return e.message;
  }
}
var Relay = class {
  /** @param {AwpSocket} socket */
  constructor(socket) {
    this.socket = socket;
    this.post = null;
    this.held = [];
    this.request = null;
    this.own = null;
    this.queued = [];
    this.holding = false;
    this.claimUntil = 0;
    this.onResponse = null;
    this.stop = () => {
    };
    socket.onmessage = (type, flags, payload) => this.#receive(type, flags, payload);
  }
  /** Connects the website: posts HELLO, then the messages held for it. */
  connect(post) {
    this.post = post;
    post({ type: HELLO, flags: 0, payload: this.socket.helloPayload });
    this.held.splice(0).forEach(post);
  }
  /**
   * Whether the website holds the claim. Airfrog keeps it while a request
   * runs and for CLAIM_MS after the response.
   */
  claimed() {
    return this.holding && ([CLAIM, TARGET_CMD, IDENTIFY].includes(this.request) || this.claimUntil > Date.now());
  }
  /** Sends the website's request, after the window's command if one waits. */
  send(type, payload) {
    if (this.own) {
      this.queued.push([type, payload]);
      return;
    }
    this.request = type;
    this.socket.send(type, payload);
  }
  /**
   * Sends the window's own AIRFROG_CMD once the website's request has its
   * response.
   * @returns {Promise<Uint8Array>} the response's fields
   */
  command(command, fields = new Uint8Array(0)) {
    return new Promise((resolve, reject) => {
      this.own = { payload: encodeAirfrogCmd({ command, fields }), resolve, reject, timer: null, sent: false };
      this.#sendOwn();
    });
  }
  #sendOwn() {
    const own = this.own;
    if (!own || own.sent || this.request !== null) {
      return;
    }
    own.sent = true;
    own.timer = setTimeout(() => this.#settleOwn("reject", new AirfrogError("TIMEOUT")), CONNECT_TIMEOUT_MS);
    try {
      this.socket.send(AIRFROG_CMD, own.payload);
    } catch (e) {
      this.#settleOwn("reject", e);
    }
  }
  #settleOwn(settle, value) {
    const own = this.own;
    this.own = null;
    clearTimeout(own.timer);
    own[settle](value);
    for (const [type, payload] of this.queued.splice(0)) {
      try {
        this.send(type, payload);
      } catch (e) {
      }
    }
  }
  /** Fails the window's command once the connection has closed. */
  closed(error) {
    if (this.own) {
      this.#settleOwn("reject", error);
    }
  }
  #receive(type, flags, payload) {
    if (!(flags & HEADER_RESPONSE)) {
      this.#toWebsite({ type, flags, payload });
    } else if (this.own?.sent) {
      if (type === AIRFROG_CMD) {
        this.#settleOwn("resolve", payload);
      } else {
        const error = type === ERROR ? errorFromPayload(payload) : null;
        this.#settleOwn("reject", error ?? new AirfrogError("INVALID_MESSAGE"));
      }
    } else {
      this.#claimAfter(this.request, type, payload);
      this.request = null;
      this.#toWebsite({ type, flags, payload });
      this.onResponse?.();
      this.#sendOwn();
    }
  }
  /** Follows the website's claim from the response to its request. */
  #claimAfter(request, type, payload) {
    const error = type === ERROR ? errorFromPayload(payload) : null;
    if (error?.code === "NOT_CLAIMED" || request === RELEASE && !error) {
      this.holding = false;
    } else if (request === CLAIM && !error) {
      this.holding = true;
    }
    if ([CLAIM, TARGET_CMD, IDENTIFY].includes(request)) {
      this.claimUntil = Date.now() + CLAIM_MS;
    }
  }
  #toWebsite(message2) {
    if (this.post) {
      this.post(message2);
    } else {
      this.held.push(message2);
    }
  }
  /**
   * Resolves once the website doesn't hold the claim, or after ms.
   * @param {number} ms
   */
  released(ms) {
    return new Promise((resolve) => {
      const deadline = Date.now() + ms;
      let timer = null;
      const check2 = () => {
        clearTimeout(timer);
        if (!this.claimed() || Date.now() >= deadline || this.socket.closed) {
          this.onResponse = null;
          resolve();
          return;
        }
        const at = this.request === null ? Math.min(this.claimUntil, deadline) : deadline;
        timer = setTimeout(check2, at - Date.now() + 1);
      };
      this.onResponse = check2;
      this.stop = () => clearTimeout(timer);
      check2();
    });
  }
};
var BridgeView = class {
  constructor(container) {
    const el = (tag, attrs = {}, text = "") => {
      const e = document.createElement(tag);
      Object.assign(e, attrs);
      if (text) {
        e.textContent = text;
      }
      return e;
    };
    this.el = el;
    this.root = el("div", { className: "stack" });
    this.lines = el("div", { id: "bridge-status", className: "stack" });
    this.lines.setAttribute("role", "status");
    this.form = el("form", { id: "bridge-login", className: "stack" });
    const label = el("label", {});
    const labelText = el("span", {}, CONNECTION.PASSWORD);
    this.password = el("input", { id: "bridge-password", type: "password", autocomplete: "current-password" });
    label.append(labelText, this.password);
    this.loginButton = el("button", { type: "submit", disabled: true }, CONNECTION.LOG_IN);
    this.password.addEventListener("input", () => {
      this.loginButton.disabled = !this.password.value;
    });
    const forgotten = el("p", { className: "note" }, BRIDGE.FORGOTTEN);
    const recovery = el(
      "a",
      { href: RECOVERY, target: "_blank", rel: "noopener" },
      RECOVERY.replace(/^https:\/\//, "")
    );
    forgotten.append(" ", recovery);
    const loginRow = el("div", { className: "row" });
    loginRow.append(this.loginButton);
    this.form.append(label, loginRow, forgotten);
    this.form.hidden = true;
    this.button = el("button", { type: "button", id: "bridge-button" });
    this.cancel = el("button", { type: "button", id: "bridge-cancel", className: "cancel" }, CONTROLS.CANCEL);
    this.buttonRow = el("div", { className: "row" });
    this.buttonRow.append(this.button, this.cancel);
    this.buttonRow.hidden = true;
    this.cancel.hidden = true;
    this.onButton = null;
    this.onCancel = null;
    this.button.addEventListener("click", () => this.onButton?.());
    this.cancel.addEventListener("click", () => this.onCancel?.());
    this.root.append(this.lines, this.form, this.buttonRow);
    container.append(this.root);
  }
  /**
   * Displays lines, each [text, kind]: kind is '' for the text colour, or
   * 'msg', 'msg ok' or 'msg bad' for a message line.
   */
  show(...lines) {
    this.lines.replaceChildren(...lines.filter(([text]) => text).map(([text, kind]) => this.el("div", kind ? { className: kind } : {}, text)));
  }
  /** One button below the lines, or none for a null label. */
  action(label, onClick = null) {
    this.form.hidden = true;
    this.buttonRow.hidden = label === null;
    this.button.textContent = label ?? "";
    this.button.className = "";
    this.cancel.hidden = true;
    this.onButton = onClick;
  }
  /**
   * Displays Allow and Cancel.
   * @returns {Promise<boolean>} whether Allow was clicked
   */
  askAllow(host, site) {
    this.show([BRIDGE.ALLOW_CONNECT(site, host), ""]);
    return new Promise((resolve) => {
      this.action(BRIDGE.ALLOW, () => resolve(true));
      this.button.className = "primary";
      this.cancel.hidden = false;
      this.onCancel = () => resolve(false);
      this.cancel.focus?.();
    });
  }
  progress(text) {
    this.show([text, "msg"]);
    this.action(null);
  }
  /**
   * @param {string} host
   * @param {string} site
   * @param {string|null} failure - why the last login failed
   * @returns {Promise<string>} the password entered
   */
  askPassword(host, site, failure) {
    this.show([BRIDGE.ENTER_PASSWORD(host, site), ""], [failure, "msg bad"]);
    this.action(null);
    this.form.hidden = false;
    this.password.value = "";
    this.loginButton.disabled = true;
    this.password.focus?.();
    return new Promise((resolve) => {
      const submit = (event) => {
        event.preventDefault?.();
        this.form.removeEventListener("submit", submit);
        this.progress(CONNECTION.LOGGING_IN);
        resolve(this.password.value);
        this.password.value = "";
      };
      this.form.addEventListener("submit", submit);
    });
  }
};
async function listed(relay, origin) {
  const list = decodeAuthorisedWebsites(await relay.command(Command.GET_AUTHORISED_WEBSITES));
  if (!list) {
    throw new AirfrogError("INVALID_MESSAGE");
  }
  return list.website.includes(origin);
}
async function startBridge(container) {
  const origin = bridgeOrigin(location.hash);
  if (!origin) {
    location.replace(`http://${location.host}/`);
    return;
  }
  const host = location.host;
  const site = siteName(origin);
  document.title = BRIDGE.TITLE(host, site);
  const view = new BridgeView(container);
  const closeWindow = () => window.close();
  const opener = window.opener;
  if (!opener) {
    view.show([BRIDGE.OPENED_DIRECTLY, "msg bad"], [BRIDGE.CONNECT_FROM(site), ""]);
    const offerClose = () => view.action(history.length === 1 ? BRIDGE.CLOSE : null, closeWindow);
    offerClose();
    window.addEventListener("pageshow", (event) => event.persisted && offerClose());
    return;
  }
  const post = (message2) => {
    try {
      opener.postMessage({ [BRIDGE_KEY]: message2 }, origin);
    } catch (e) {
    }
  };
  const ended = (heading, reason, error) => {
    view.show([heading, "msg bad"], [reason, ""], [BRIDGE.RECONNECT_FROM(site), ""]);
    view.action(BRIDGE.CLOSE, closeWindow);
    post({ close: errorToBridge(new AirfrogError(error.code, error.detail, reason)) });
  };
  view.progress(CONNECTION.CONNECTING);
  let socket = null;
  let password = null;
  while (!socket) {
    try {
      socket = await AwpSocket.open(host, password);
    } catch (e) {
      if (["PASSWORD_REQUIRED", "LOGIN_FAILED", "LOGIN_BLOCKED"].includes(e.code)) {
        password = await view.askPassword(host, site, e.code === "PASSWORD_REQUIRED" ? null : e.message);
        continue;
      }
      ended(BRIDGE.NOT_CONNECTED(site, host), reasonFor(e, host, site), e);
      return;
    }
  }
  const relay = new Relay(socket);
  let connected = false;
  let ending = null;
  let checkTimer = null;
  const close = (reason, code) => {
    ending = reason ?? CONNECTION.CLOSED;
    socket.close(code, new AirfrogError("CLOSED", null, ending));
  };
  const closeAndLeave = (reason, code) => {
    close(reason, code);
    window.close();
  };
  const failure = (e, reason) => {
    if (socket.closed) {
      return null;
    }
    if (e.code === "TIMEOUT") {
      return BRIDGE.NOT_RESPONDING(host);
    }
    return e.code === "INVALID_MESSAGE" ? BRIDGE.INVALID_FROM_AIRFROG(host) : reason;
  };
  const fromPage = (event) => {
    if (event.source !== opener || event.origin !== origin) {
      return;
    }
    const message2 = event.data?.[BRIDGE_KEY];
    if (!message2) {
      return;
    }
    if (message2.close) {
      closeAndLeave(null, message2.close.closeCode);
      return;
    }
    const refused = refusal(message2, site);
    if (refused) {
      close(refused);
      return;
    }
    try {
      relay.send(message2.type, message2.payload);
    } catch (e) {
    }
  };
  const leaving = () => close(BRIDGE.WINDOW_CLOSED(host));
  const openerPoll = setInterval(() => {
    if (opener.closed) {
      closeAndLeave(null);
    }
  }, OPENER_POLL_MS);
  socket.onclose = (error) => {
    clearInterval(openerPoll);
    clearTimeout(checkTimer);
    relay.stop();
    relay.closed(error);
    window.removeEventListener("message", fromPage);
    window.removeEventListener("pagehide", leaving);
    ended(
      connected ? BRIDGE.DISCONNECTED(site, host) : BRIDGE.NOT_CONNECTED(site, host),
      ending ?? reasonFor(error, host, site),
      error
    );
  };
  window.addEventListener("pagehide", leaving);
  try {
    if (!await listed(relay, origin)) {
      if (!await view.askAllow(host, site)) {
        closeAndLeave(BRIDGE.WINDOW_CLOSED(host));
        return;
      }
      view.progress(CONNECTION.CONNECTING);
      try {
        await relay.command(Command.ADD_AUTHORISED_WEBSITE, encodeAuthorisedWebsite({ website: origin }));
      } catch (e) {
        if (!(e.code === "CODE" && e.detail === ERROR_EXISTS)) {
          const reason = failure(e, e.code === "NO_SPACE" ? BRIDGE.TOO_MANY_WEBSITES(host) : BRIDGE.ADD_FAILED(site, host));
          if (reason) {
            close(reason);
          }
          return;
        }
      }
    }
  } catch (e) {
    const reason = failure(e, BRIDGE.READ_FAILED(host));
    if (reason) {
      close(reason);
    }
    return;
  }
  const check2 = async () => {
    let ok;
    try {
      ok = await listed(relay, origin);
    } catch (e) {
      if (socket.closed) {
        return;
      }
      if (e.code === "TIMEOUT" || e.code === "INVALID_MESSAGE") {
        close(failure(e, ""));
        return;
      }
      ok = null;
    }
    if (ok) {
      checkTimer = setTimeout(check2, CHECK_MS);
      return;
    }
    if (relay.claimed()) {
      await relay.released(CHECK_MS);
      if (socket.closed) {
        return;
      }
      if (ok === null) {
        try {
          ok = await listed(relay, origin);
        } catch (e) {
          if (!socket.closed) {
            close(failure(e, BRIDGE.READ_FAILED(host)));
          }
          return;
        }
        if (ok) {
          checkTimer = setTimeout(check2, CHECK_MS);
          return;
        }
      }
    }
    close(ok === null ? BRIDGE.READ_FAILED(host) : BRIDGE.REVOKED(site));
  };
  connected = true;
  window.addEventListener("message", fromPage);
  view.show([BRIDGE.CONNECTED(site, host), "msg ok"], [BRIDGE.CLOSING_DISCONNECTS(site, host), ""]);
  view.action(BRIDGE.DISCONNECT, () => closeAndLeave(BRIDGE.WINDOW_DISCONNECTED(host)));
  relay.connect(post);
  checkTimer = setTimeout(check2, CHECK_MS);
}

// js/setup/dom.js
function h(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v === void 0 || v === null || v === false) {
      continue;
    }
    if (k.startsWith("on") && typeof v === "function") {
      e.addEventListener(k.slice(2), v);
    } else if (k === "class" || k === "for" || k.startsWith("data-") || k.startsWith("aria-")) {
      e.setAttribute(k, v === true ? "" : v);
    } else {
      e[k] = v;
    }
  }
  e.append(...children.flat().filter((c) => c !== null && c !== void 0 && c !== false));
  return e;
}
function placeTip(mark) {
  const box = mark.lastChild;
  const r = mark.getBoundingClientRect();
  box.style.top = "0px";
  box.style.left = "0px";
  const above = r.top - box.offsetHeight - 6;
  box.style.top = `${above >= 8 ? above : r.bottom + 6}px`;
  box.style.left = `${Math.max(8, Math.min(r.left - 8, window.innerWidth - box.offsetWidth - 8))}px`;
}
function setTip(mark, open, pinned = false) {
  mark.classList.toggle("open", open);
  mark.classList.toggle("pinned", open && pinned);
  if (open) {
    placeTip(mark);
  }
}
function tip(text) {
  const mark = h("span", {
    class: "tip",
    tabindex: 0,
    role: "button",
    "aria-label": text,
    // Hover with a mouse only: a tap opens a tip with the click.
    onpointerenter: (e) => e.pointerType === "mouse" && setTip(mark, true, mark.classList.contains("pinned")),
    onpointerleave: (e) => e.pointerType === "mouse" && setTip(mark, mark.classList.contains("pinned"), mark.classList.contains("pinned")),
    onfocus: () => setTip(mark, true, mark.classList.contains("pinned")),
    onblur: () => setTip(mark, false),
    onclick: (e) => {
      e.preventDefault();
      e.stopPropagation();
      const pinned = mark.classList.contains("pinned");
      for (const other of document.querySelectorAll(".tip.open")) {
        if (other !== mark) {
          setTip(other, false);
        }
      }
      setTip(mark, !pinned, !pinned);
      if (pinned) {
        mark.blur();
      }
    }
  }, "?", h("span", { class: "tip-box", role: "tooltip" }, text));
  return mark;
}
if (typeof document !== "undefined") {
  document.addEventListener("pointerdown", (e) => {
    for (const open of document.querySelectorAll(".tip.open")) {
      if (!open.contains(e.target)) {
        setTip(open, false);
      }
    }
  });
  document.addEventListener("scroll", () => {
    for (const open of document.querySelectorAll(".tip.open")) {
      placeTip(open);
    }
  }, true);
}
function card(title, help, ...children) {
  const pill = h("span", { class: "pill", hidden: true });
  const e = h("section", { class: "card" }, h(
    "div",
    { class: "card-head" },
    h("h2", {}, title),
    help ? tip(help) : null,
    pill
  ), ...children);
  e.pill = pill;
  return e;
}
function rows(list) {
  const values = {};
  const labels = {};
  const dl = h("dl", { class: "kv" });
  for (const [key, label, help] of list) {
    values[key] = h("dd", {}, VALUES.NONE);
    labels[key] = h("dt", {}, label, help ? tip(help) : null);
    dl.append(labels[key], values[key]);
  }
  return { element: dl, values, labels };
}
function link(url, text = url, { newTab = false } = {}) {
  return h("a", { href: url, target: newTab ? "_blank" : null, rel: newTab ? "noopener" : null }, text);
}
function message() {
  const e = h("div", { class: "msg", role: "status" });
  e.say = (text, tone = "") => {
    e.replaceChildren(...[].concat(text ?? ""));
    e.className = tone ? `msg ${tone}` : "msg";
  };
  return e;
}
function button(text, onclick, attrs = {}) {
  return h("button", { type: "button", onclick, ...attrs }, text);
}
function check(name, label, help = null, attrs = {}) {
  const box = h("input", { type: "checkbox", name, ...attrs });
  return { box, element: h("label", { class: "check" }, box, label, help ? tip(help) : null) };
}
function prompt() {
  const element = h("div", { class: "prompt", role: "alertdialog", hidden: true });
  const ask = (text, action, onConfirm, { danger = false } = {}) => {
    const cancel = button(CONTROLS.CANCEL, () => {
      element.hidden = true;
    }, { class: "cancel" });
    element.replaceChildren(h("div", {}, text), h(
      "div",
      { class: "row" },
      button(action, () => {
        element.hidden = true;
        onConfirm();
      }, { class: danger ? "danger" : "primary" }),
      cancel
    ));
    element.hidden = false;
    cancel.focus?.();
  };
  return { element, ask };
}

// js/airfrog.js
var IDENTIFY_TIMEOUT_MS = 15e3;
var RESET_TIMEOUT_MS = 35e3;
var EXT_WRITE_TIMEOUT_MS = 1e4;
var EXT_FINISH_TIMEOUT_MS = 3e4;
var EMPTY = new Uint8Array(0);
var WINDOW_POLL_MS = 500;
var BRIDGE_CLOSE_WAIT_MS = 2e3;
var WINDOW_FEATURES = "popup,width=560,height=600";
var EXTENSION_CONNECT_MS = 1e4;
var BridgePipe = class _BridgePipe {
  /**
   * @param {Window} win - the bridge window
   * @param {string} origin - Airfrog's origin
   * @returns {Promise<{pipe: BridgePipe, hello: Hello}>} once the window
   *          forwards HELLO
   */
  static start(win, origin) {
    return new Promise((resolve, reject) => {
      const pipe = new _BridgePipe(win, origin);
      pipe.opening = { resolve, reject };
    });
  }
  constructor(win, origin) {
    this.win = win;
    this.origin = origin;
    this.closed = null;
    this.heard = false;
    this.opening = null;
    this.held = [];
    this._onmessage = null;
    this.onclose = null;
    this.listener = (event) => this.receive(event);
    this.leaving = () => this.close(void 0, void 0, true);
    window.addEventListener("message", this.listener);
    window.addEventListener("pagehide", this.leaving);
    this.poll = setInterval(() => {
      if (this.win.closed) {
        this.ended(new AirfrogError("CLOSED", null, BRIDGE.WINDOW_CLOSED(new URL(origin).host)));
      }
    }, WINDOW_POLL_MS);
  }
  set onmessage(handler) {
    this._onmessage = handler;
    const held = this.held;
    this.held = [];
    for (const [type, flags, payload] of held) {
      handler(type, flags, payload);
    }
  }
  get onmessage() {
    return this._onmessage;
  }
  receive(event) {
    if (this.closed || event.source !== this.win || event.origin !== this.origin) {
      return;
    }
    const message2 = event.data?.[BRIDGE_KEY];
    if (!message2) {
      return;
    }
    this.heard = true;
    if (message2.close) {
      this.ended(errorFromBridge(message2.close));
      return;
    }
    const { type, flags, payload } = message2;
    if (!Number.isInteger(type) || !Number.isInteger(flags) || !(payload instanceof Uint8Array)) {
      this.close(void 0, new AirfrogError("INVALID_MESSAGE", "malformed message from the bridge window"));
      return;
    }
    if (this.opening) {
      this.hello(type, payload);
    } else if (this._onmessage) {
      this._onmessage(type, flags, payload);
    } else {
      this.held.push([type, flags, payload]);
    }
  }
  hello(type, payload) {
    const hello = type === HELLO ? Hello.parse(payload) : null;
    if (!hello) {
      const what = type === HELLO ? `${payload.length}-byte HELLO` : `${hex(type)} before HELLO`;
      this.close(CLOSE_PROTOCOL_ERROR, new AirfrogError("INVALID_MESSAGE", what));
      return;
    }
    if (hello.revision < 1) {
      this.close(CLOSE_PROTOCOL_ERROR, new AirfrogError("INVALID_MESSAGE", `AWP revision ${hello.revision}`));
      return;
    }
    const { resolve } = this.opening;
    this.opening = null;
    resolve({ pipe: this, hello });
  }
  /**
   * @param {number} type
   * @param {Uint8Array} payload
   */
  send(type, payload) {
    if (this.closed) {
      throw this.closed;
    }
    this.win.postMessage({ [BRIDGE_KEY]: { type, payload } }, this.origin);
  }
  /**
   * Closes the connection and the bridge window.
   * @param {number} [code] - the close code the bridge window closes the
   *        WebSocket with
   * @param {AirfrogError} [error] - the reason recorded, CLOSED by default
   * @param {boolean} [leaving] - whether the page is being left
   */
  close(code, error, leaving = false) {
    if (this.closed) {
      return;
    }
    try {
      this.win.postMessage({ [BRIDGE_KEY]: { close: { closeCode: code } } }, this.origin);
      if (this.heard && !leaving) {
        setTimeout(() => this.win.close(), BRIDGE_CLOSE_WAIT_MS);
      } else {
        this.win.close();
      }
    } catch (e) {
    }
    this.ended(error ?? new AirfrogError("CLOSED", null, CONNECTION.CLOSED));
  }
  ended(error) {
    if (this.closed) {
      return;
    }
    this.closed = error;
    clearInterval(this.poll);
    window.removeEventListener("message", this.listener);
    window.removeEventListener("pagehide", this.leaving);
    if (this.opening) {
      this.opening.reject(error);
      this.opening = null;
      return;
    }
    this.onclose?.(error);
  }
};
var FramePipe = class _FramePipe {
  /**
   * Posts a connection request to the parent window.
   * @param {Window} parent
   * @returns {Promise<{pipe: FramePipe, hello: Hello, extension: string, limited: boolean}>}
   *          once the parent posts HELLO
   */
  static start(parent) {
    return new Promise((resolve, reject) => {
      const pipe = new _FramePipe(parent);
      pipe.opening = { resolve, reject };
      parent.postMessage({ [EXTENSION_KEY]: { connect: true, id: pipe.id } }, "*");
    });
  }
  constructor(parent) {
    this.parent = parent;
    this.id = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
    this.origin = null;
    this.closed = null;
    this.opening = null;
    this.held = [];
    this._onmessage = null;
    this.onclose = null;
    this.listener = (event) => this.receive(event);
    window.addEventListener("message", this.listener);
    this.timer = setTimeout(() => this.ended(new AirfrogError(
      "CONNECT",
      "no answer from the parent window",
      EXTENSIONS.NOT_IN_AIRFROG_UI
    )), EXTENSION_CONNECT_MS);
  }
  set onmessage(handler) {
    this._onmessage = handler;
    const held = this.held;
    this.held = [];
    for (const [type, flags, payload] of held) {
      handler(type, flags, payload);
    }
  }
  get onmessage() {
    return this._onmessage;
  }
  receive(event) {
    if (this.closed || event.source !== this.parent || this.origin && event.origin !== this.origin) {
      return;
    }
    const message2 = event.data?.[EXTENSION_KEY];
    if (!message2 || message2.id !== this.id) {
      return;
    }
    if (message2.close) {
      this.ended(errorFromBridge(message2.close));
      return;
    }
    const { type, flags, payload } = message2;
    if (!Number.isInteger(type) || !Number.isInteger(flags) || !(payload instanceof Uint8Array)) {
      this.close(void 0, new AirfrogError("INVALID_MESSAGE", "malformed message from the Airfrog UI"));
      return;
    }
    if (this.opening) {
      this.hello(event.origin, message2);
    } else if (this._onmessage) {
      this._onmessage(type, flags, payload);
    } else {
      this.held.push([type, flags, payload]);
    }
  }
  hello(origin, { type, payload, extension, limited }) {
    const hello = type === HELLO ? Hello.parse(payload) : null;
    if (!hello || hello.revision < 1 || typeof extension !== "string" || typeof limited !== "boolean") {
      this.close(void 0, new AirfrogError("INVALID_MESSAGE", `${hex(type)} as the Airfrog UI's HELLO`));
      return;
    }
    clearTimeout(this.timer);
    this.origin = origin;
    const { resolve } = this.opening;
    this.opening = null;
    this.postHeight();
    resolve({ pipe: this, hello, extension, limited });
  }
  /**
   * Posts the page's height to the Airfrog UI, and again each time it
   * changes, so the frame is as high as the page. It goes on after the
   * connection closes, when the page displays why.
   */
  postHeight() {
    if (typeof ResizeObserver !== "function") {
      return;
    }
    const post = () => {
      const height = Math.ceil(document.documentElement.getBoundingClientRect().height);
      this.parent.postMessage({ [EXTENSION_KEY]: { height, id: this.id } }, this.origin);
    };
    new ResizeObserver(post).observe(document.documentElement);
  }
  /**
   * @param {number} type
   * @param {Uint8Array} payload
   */
  send(type, payload) {
    if (this.closed) {
      throw this.closed;
    }
    this.parent.postMessage({ [EXTENSION_KEY]: { type, payload, id: this.id } }, this.origin);
  }
  /**
   * Closes the connection.
   * @param {number} [code] - the close code the Airfrog UI closes the
   *        WebSocket with
   * @param {AirfrogError} [error] - the reason recorded, CLOSED by default
   */
  close(code, error) {
    if (this.closed) {
      return;
    }
    if (this.origin) {
      this.parent.postMessage({ [EXTENSION_KEY]: { close: { closeCode: code }, id: this.id } }, this.origin);
    }
    this.ended(error ?? new AirfrogError("CLOSED", null, CONNECTION.CLOSED));
  }
  ended(error) {
    if (this.closed) {
      return;
    }
    this.closed = error;
    clearTimeout(this.timer);
    window.removeEventListener("message", this.listener);
    if (this.opening) {
      this.opening.reject(error);
      this.opening = null;
      return;
    }
    this.onclose?.(error);
  }
};
var Airfrog = class _Airfrog extends EventTarget {
  #host;
  #hello;
  #pipe;
  #target = new TargetInfo();
  #targetSeen = false;
  #closed = null;
  #claims = 0;
  #pending = null;
  #queue = Promise.resolve();
  /** @type {Map<string, Extension>} */
  #extensions = /* @__PURE__ */ new Map();
  /** In an extension UI, its extension's name */
  #own = null;
  /** Whether only what an extension UI may send is sent */
  #limited = false;
  /**
   * Use `connect()`, `connectBridge()` or `connectExtension()`.
   */
  constructor(host, hello, pipe, { extension = null, limited = false } = {}) {
    super();
    this.#host = host;
    this.#own = extension;
    this.#limited = limited;
    this.#hello = hello;
    this.#pipe = pipe;
    pipe.onclose = (error) => this.#ended(error);
    pipe.onmessage = (type, flags, payload) => this.#receive(type, flags, payload);
  }
  /**
   * Opens a WebSocket to Airfrog, logs in when Airfrog has a password and
   * reads the first TARGET. For Airfrog's home page: Airfrog accepts a
   * WebSocket only from a page it served.
   * @param {string} host - Airfrog's hostname, its hostname with .local or
   *        its IP address, with :port when it isn't 80
   * @param {string|null} [password] - ignored when Airfrog doesn't have
   *        one. Without one, where Airfrog has one, the connection closes
   *        with PASSWORD_REQUIRED
   * @returns {Promise<Airfrog>}
   */
  static async connect(host, password = null) {
    const socket = await AwpSocket.open(host, password);
    const airfrog = new _Airfrog(host, socket.hello, socket);
    await airfrog.#firstTarget();
    return airfrog;
  }
  /**
   * Opens the bridge window: Airfrog's home page in a new window, which
   * logs in to Airfrog and relays messages between this page and Airfrog.
   * For every page other than Airfrog's home page. Call it from a click,
   * because a browser opens a window only then.
   *
   * Resolves once the user has logged in in the bridge window. Rejects with
   * CLOSED when the user closes that window first.
   * @param {string} host - as for `connect()`
   * @returns {Promise<Airfrog>}
   */
  static async connectBridge(host) {
    let url;
    try {
      url = new URL(`http://${host}`);
    } catch (e) {
      throw new AirfrogError("CONNECT", `invalid host ${host}`, CONNECTION.INVALID_ADDRESS(host));
    }
    const win = window.open(`http://${host}/#bridge=${location.origin}`, "_blank", WINDOW_FEATURES);
    if (!win) {
      throw new AirfrogError(
        "CONNECT",
        "window.open() returned null",
        BRIDGE.BLOCKED(url.host, siteName(location.origin))
      );
    }
    const origin = url.origin;
    const { pipe, hello } = await BridgePipe.start(win, origin);
    const airfrog = new _Airfrog(host, hello, pipe);
    await airfrog.#firstTarget();
    return airfrog;
  }
  /**
   * Connects an extension UI to Airfrog through the Airfrog UI that
   * contains it in a frame. The Airfrog UI logs in and forwards only what
   * an extension UI may send: CLAIM, RELEASE, TARGET_CMD, IDENTIFY,
   * AIRFROG_CMD get commands and EXT_CMD to its own extension. Other
   * AIRFROG_CMD commands fail with NOT_PERMITTED without being sent.
   *
   * Fails with CONNECT in a page that isn't inside the Airfrog UI.
   * @returns {Promise<Airfrog>}
   */
  static async connectExtension() {
    if (typeof window === "undefined" || window.parent === window) {
      throw new AirfrogError("CONNECT", "not in a frame", EXTENSIONS.NOT_IN_AIRFROG_UI);
    }
    const { pipe, hello, extension, limited } = await FramePipe.start(window.parent);
    const airfrog = new _Airfrog(null, hello, pipe, { extension, limited });
    await airfrog.#firstTarget();
    return airfrog;
  }
  /** @returns {string|null} the host the connection was opened with, null in an extension UI */
  getHost() {
    return this.#host;
  }
  /** @returns {number} HELLO's AWP revision */
  getRevision() {
    return this.#hello.revision;
  }
  /** @returns {number} HELLO's max_transfer: the most bulk data in one request or response */
  getMaxTransfer() {
    return this.#hello.maxTransfer;
  }
  /** @returns {TargetInfo} the last TARGET Airfrog sent */
  getTarget() {
    return this.#target;
  }
  /** @returns {boolean} whether the connection is closed */
  isClosed() {
    return this.#closed !== null;
  }
  /**
   * Closes the connection. Through the bridge, it also closes Airfrog's
   * window.
   */
  close() {
    this.#pipe.close();
  }
  /**
   * Waits for a TARGET that meets condition. The last TARGET counts.
   * @param {number} timeoutMs
   * @param {function(TargetInfo): boolean} condition
   * @returns {Promise<TargetInfo|null>} null when none arrived in time
   */
  waitForTarget(timeoutMs, condition) {
    if (condition(this.#target)) {
      return Promise.resolve(this.#target);
    }
    if (this.#closed) {
      return Promise.reject(this.#closed);
    }
    return new Promise((resolve, reject) => {
      const done = (finish, value) => {
        clearTimeout(timer);
        this.removeEventListener("target", onTarget);
        this.removeEventListener("close", onClose);
        finish(value);
      };
      const onTarget = (event) => {
        if (condition(event.detail)) {
          done(resolve, event.detail);
        }
      };
      const onClose = (event) => done(reject, event.detail);
      const timer = setTimeout(() => done(resolve, null), timeoutMs);
      this.addEventListener("target", onTarget);
      this.addEventListener("close", onClose);
    });
  }
  /**
   * Adds one to this connection's claims. The first sends CLAIM and waits
   * up to timeoutMs for its response. Each claim is ended by one
   * `release()`.
   * @param {number} timeoutMs
   * @returns {Promise<void>}
   */
  claim(timeoutMs) {
    return this.#locked(async () => {
      if (this.#claims === 0) {
        await this.#request(CLAIM, new Uint8Array(0), timeoutMs);
      }
      this.#claims += 1;
    });
  }
  /**
   * Ends one claim. The last sends RELEASE without waiting for its
   * response.
   */
  release() {
    if (this.#claims === 0) {
      console.warn("Airfrog claim released more times than it was claimed");
      return;
    }
    this.#claims -= 1;
    if (this.#claims === 0) {
      this.#locked(() => this.#request(RELEASE, new Uint8Array(0), CONNECT_TIMEOUT_MS)).catch((e) => console.debug(`RELEASE failed: ${e.message}`));
    }
  }
  /**
   * Sends TARGET_CMD to service's operation with fields. Where this
   * connection holds a claim and Airfrog has ended it, CLAIM and the
   * command are sent again, once.
   * @param {number} service
   * @param {number} operation
   * @param {Uint8Array} fields
   * @param {number} timeoutMs - limits the wait for the response
   * @returns {Promise<Uint8Array>} the response's fields
   */
  targetCmd(service, operation, fields, timeoutMs) {
    if (!Number.isInteger(service) || !Number.isInteger(operation)) {
      throw new TypeError("targetCmd() requires a service and an operation");
    }
    const request = encodeTargetCmd({ service, operation, fields });
    return this.#locked(async () => {
      try {
        return await this.#request(TARGET_CMD, request, timeoutMs);
      } catch (e) {
        if (e.code !== "NOT_CLAIMED" || this.#claims === 0) {
          throw e;
        }
        console.debug("Airfrog ended the claim, claiming again");
        await this.#request(CLAIM, new Uint8Array(0), timeoutMs);
        return await this.#request(TARGET_CMD, request, timeoutMs);
      }
    });
  }
  /**
   * Sends AIRFROG_CMD command with fields.
   * @param {number} command
   * @param {Uint8Array} fields
   * @param {number} timeoutMs - limits the wait for the response
   * @returns {Promise<Uint8Array>} the response's fields
   */
  airfrogCmd(command, fields, timeoutMs) {
    return this.#locked(() => this.#airfrogCmd(command, fields, timeoutMs));
  }
  #airfrogCmd(command, fields, timeoutMs) {
    if (this.#limited) {
      const name = Object.keys(Command).find((k) => Command[k] === command);
      if (!name?.startsWith("GET_")) {
        const what = `AIRFROG_CMD ${name ?? hex(command)}`;
        return Promise.reject(new AirfrogError("NOT_PERMITTED", what, EXTENSIONS.NOT_PERMITTED(what)));
      }
    }
    return this.#request(AIRFROG_CMD, encodeAirfrogCmd({ command, fields }), timeoutMs);
  }
  /**
   * Resets the target into its bootloader with RESET's RESET_BOOT, which
   * uses the active pin map's reset and boot pins. It claims the target for
   * the operation.
   *
   * Airfrog sends TARGET with state IDENTIFYING before the response, and
   * TARGET again once identification completes. See `waitForTarget()`.
   * @returns {Promise<void>}
   */
  async resetBoot() {
    await this.#claimed(() => this.targetCmd(
      Service.RESET,
      Operation.RESET_RESET_BOOT,
      new Uint8Array(0),
      RESET_TIMEOUT_MS
    ));
  }
  /**
   * Resets the target with RESET's RESET_PINS. It claims the target for the
   * operation. RESET_PINS is supported whatever Airfrog's pin map.
   *
   * Airfrog sends TARGET as for `resetBoot()`.
   * @param {{resetPin: string, resetLevel: number, resetMs: number,
   *          bootPin: string|null, bootLevel: number, bootDelayMs: number,
   *          bootHoldMs: number}} pins - a pin is a connector name, for
   *        example J1-4, or a name in the active pin map. bootPin is null
   *        for a reset without a boot pin
   * @returns {Promise<void>}
   */
  async resetPins(pins) {
    checkPin(pins.resetPin);
    if (pins.bootPin) {
      checkPin(pins.bootPin);
    }
    const fields = encodeResetPins({ ...pins, bootLevel: pins.bootLevel ?? PinLevel.LOW });
    await this.#claimed(() => this.targetCmd(Service.RESET, Operation.RESET_RESET_PINS, fields, RESET_TIMEOUT_MS));
  }
  /**
   * Makes Airfrog identify the target at once with IDENTIFY, checking each
   * of firmware over its own protocol, in order. It claims the target for
   * the request.
   *
   * Airfrog sends the new TARGET before the response.
   * @param {number} flags - IdentifyFlag's bits
   * @param {Array<number>} firmware - firmware IDs
   * @returns {Promise<Array<number>>} an IdentifyResult per firmware ID
   */
  async identify(flags, firmware) {
    const request = encodeIdentify({ flags, firmware });
    const response = await this.#claimed(
      () => this.#locked(() => this.#request(IDENTIFY, request, IDENTIFY_TIMEOUT_MS))
    );
    const f = decodeIdentifyResponse(response);
    if (!f || f.count !== firmware.length) {
      throw this.#fail(new AirfrogError("INVALID_MESSAGE", `${response.length}-byte IDENTIFY response`));
    }
    return f.result;
  }
  /**
   * Sets, changes or removes Airfrog's password with AIRFROG_CMD
   * SET_PASSWORD. The password doesn't leave this page: Airfrog receives K,
   * derived with a new random salt and HELLO's iterations.
   *
   * Airfrog then closes every connection, this one included, with
   * PASSWORD_CHANGED, which the `close` event reports.
   * @param {string} password - an empty password removes it
   * @returns {Promise<void>}
   */
  async setPassword(password) {
    let fields = encodeSetPassword({});
    if (password !== "") {
      const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
      fields = encodeSetPassword({ key: passwordKey(password, salt, this.#hello.iterations), salt });
    }
    await this.airfrogCmd(Command.SET_PASSWORD, fields, CONNECT_TIMEOUT_MS);
  }
  /**
   * Reads the installed extensions with AIRFROG_CMD GET_EXTENSIONS.
   * @returns {Promise<Array<{name: string, flags: number, wasmState: number, wasmReason: number,
   *          model: number, wamr: string}>>} in list order. flags are
   *          ExtensionFlag's, wasmState WasmState's and wasmReason
   *          WasmReason's. model and wamr are the extension image's, wamr
   *          as '2.4.5'
   */
  async getExtensions() {
    const response = await this.airfrogCmd(Command.GET_EXTENSIONS, EMPTY, CONNECT_TIMEOUT_MS);
    const f = decodeExtensions(response);
    if (!f) {
      throw this.#fail(new AirfrogError("INVALID_MESSAGE", `${response.length}-byte GET_EXTENSIONS response`));
    }
    return f.entries.map(({ flags, wasmState, wasmReason, header }) => ({
      name: header.name,
      flags,
      wasmState,
      wasmReason,
      model: header.model,
      wamr: header.wamr.join(".")
    }));
  }
  /**
   * Installs an extension image with EXT_BEGIN, EXT_WRITE and EXT_FINISH.
   * An image whose extension is installed updates it.
   * @param {Uint8Array} image - the extension image, unchanged
   * @param {number} flags - ExtensionFlag's TAB and SIDE_LOADED
   * @returns {Promise<void>}
   */
  async installExtension(image, flags) {
    const max = this.getMaxTransfer();
    await this.#locked(async () => {
      await this.#airfrogCmd(
        Command.EXT_BEGIN,
        encodeExtBegin({ size: image.length, sha256: sha256(image), flags }),
        EXT_WRITE_TIMEOUT_MS
      );
      for (let offset = 0; offset < image.length; offset += max) {
        await this.#airfrogCmd(
          Command.EXT_WRITE,
          encodeOtaWrite({ offset, data: image.subarray(offset, offset + max) }),
          EXT_WRITE_TIMEOUT_MS
        );
      }
      await this.#airfrogCmd(Command.EXT_FINISH, EMPTY, EXT_FINISH_TIMEOUT_MS);
    });
  }
  /**
   * Removes an extension with AIRFROG_CMD EXT_REMOVE.
   * @param {string} name - the extension name
   * @returns {Promise<void>}
   */
  async removeExtension(name) {
    await this.airfrogCmd(Command.EXT_REMOVE, encodeExtensionName({ name }), CONNECT_TIMEOUT_MS);
  }
  /**
   * Sets the list order and the Tab checkboxes with AIRFROG_CMD
   * SET_EXTENSIONS. Every installed extension is listed once.
   * @param {Array<{name: string, flags: number}>} entries - in the new
   *        order. flags are SetExtensionFlag's
   * @returns {Promise<void>}
   */
  async setExtensions(entries) {
    await this.airfrogCmd(Command.SET_EXTENSIONS, encodeSetExtensions({ entries }), CONNECT_TIMEOUT_MS);
  }
  /**
   * Reads an installed extension's metadata with AIRFROG_CMD
   * GET_EXTENSION_METADATA. Metadata that isn't JSON fails with
   * INVALID_MESSAGE and the connection stays open.
   * @param {string} name - the extension name
   * @returns {Promise<object>} extension-meta.json, parsed
   */
  async getExtensionMetadata(name) {
    const response = await this.airfrogCmd(
      Command.GET_EXTENSION_METADATA,
      encodeExtensionName({ name }),
      CONNECT_TIMEOUT_MS
    );
    try {
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(response));
    } catch (e) {
      throw new AirfrogError("INVALID_MESSAGE", `${response.length}-byte GET_EXTENSION_METADATA response, not JSON`);
    }
  }
  /**
   * The extension's WASM module, for EXT_CMD and EXT_NOTIFY. Each call with
   * the same name returns the same Extension.
   * @param {string} [name] - the extension name. In an extension UI it
   *        defaults to its own extension, the only one it reaches. Another
   *        name fails at the first command with OUT_OF_RANGE
   * @returns {Extension}
   */
  extension(name = this.#own) {
    if (typeof name !== "string" || !name) {
      throw new TypeError("extension() requires the extension name");
    }
    let extension = this.#extensions.get(name);
    if (!extension) {
      extension = new Extension((data, timeoutMs) => this.#extCmd(name, data, timeoutMs));
      this.#extensions.set(name, extension);
    }
    return extension;
  }
  #extCmd(name, data, timeoutMs) {
    if (data.length > MAX_TRANSFER_MIN) {
      return Promise.reject(new AirfrogError(
        "TRANSFER_TOO_LARGE",
        data.length,
        ERRORS.TRANSFER_TOO_LARGE(data.length, MAX_TRANSFER_MIN)
      ));
    }
    const request = encodeExtCmd({ name, data });
    return this.#locked(() => this.#request(EXT_CMD, request, timeoutMs)).catch((e) => {
      if (e.code === "OUT_OF_RANGE") {
        throw new AirfrogError(e.code, name, EXTENSIONS.NOT_INSTALLED(name));
      }
      throw e.code === "NOT_OFFERED" || e.code === "NOT_RUNNING" ? new AirfrogError(e.code, name) : e;
    });
  }
  async #claimed(operation) {
    await this.claim(CONNECT_TIMEOUT_MS);
    try {
      return await operation();
    } finally {
      this.release();
    }
  }
  /** Runs fn once every earlier request has finished. */
  #locked(fn) {
    const result = this.#queue.then(() => fn());
    this.#queue = result.catch(() => {
    });
    return result;
  }
  /** Sends a request and resolves to its response's payload. */
  #request(type, payload, timeoutMs) {
    if (this.#closed) {
      return Promise.reject(this.#closed);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.#fail(new AirfrogError("TIMEOUT")), timeoutMs);
      this.#pending = { type, resolve, reject, timer };
      try {
        this.#pipe.send(type, payload);
      } catch (e) {
        this.#fail(e);
      }
    });
  }
  #finish(settle, value) {
    const pending = this.#pending;
    this.#pending = null;
    clearTimeout(pending.timer);
    pending[settle](value);
  }
  #firstTarget() {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#fail(new AirfrogError("TIMEOUT"));
      }, CONNECT_TIMEOUT_MS);
      const onTarget = () => {
        done();
        resolve();
      };
      const onClose = (event) => {
        done();
        reject(event.detail);
      };
      const done = () => {
        clearTimeout(timer);
        this.removeEventListener("target", onTarget);
        this.removeEventListener("close", onClose);
      };
      if (this.#closed) {
        done();
        reject(this.#closed);
        return;
      }
      if (this.#targetSeen) {
        done();
        resolve();
        return;
      }
      this.addEventListener("target", onTarget);
      this.addEventListener("close", onClose);
    });
  }
  #receive(type, flags, payload) {
    const pending = this.#pending;
    if (!(flags & HEADER_RESPONSE)) {
      if (type === TARGET) {
        this.#setTarget(payload);
      } else if (type === EXT_NOTIFY) {
        this.#notify(payload);
      } else if (isKnown(type)) {
        this.#fail(new AirfrogError("INVALID_MESSAGE", `unrequested message type ${hex(type)}`));
      }
    } else if (pending && type === pending.type) {
      if (type === TARGET && !this.#setTarget(payload)) {
        return;
      }
      this.#finish("resolve", payload);
    } else if (pending && type === ERROR) {
      const e = errorFromPayload(payload);
      if (e) {
        this.#finish("reject", e);
      } else {
        this.#fail(new AirfrogError("INVALID_MESSAGE", `${payload.length}-byte ERROR`));
      }
    } else if (isKnown(type)) {
      const what = pending ? `${hex(type)} in response to ${hex(pending.type)}` : `unrequested response ${hex(type)}`;
      this.#fail(new AirfrogError("INVALID_MESSAGE", what));
    }
  }
  #notify(payload) {
    const f = decodeExtCmd(payload);
    if (!f) {
      this.#fail(new AirfrogError("INVALID_MESSAGE", `${payload.length}-byte EXT_NOTIFY`));
      return;
    }
    this.#extensions.get(f.name)?.dispatchEvent(new CustomEvent("notify", { detail: f.data.slice() }));
  }
  /** @returns {boolean} whether payload is a valid TARGET */
  #setTarget(payload) {
    const target = TargetInfo.parse(payload);
    if (!target) {
      this.#fail(new AirfrogError("INVALID_MESSAGE", `${payload.length}-byte TARGET`));
      return false;
    }
    this.#target = target;
    this.#targetSeen = true;
    this.dispatchEvent(new CustomEvent("target", { detail: target }));
    return true;
  }
  /**
   * Closes the connection after a failure. INVALID_MESSAGE closes it with
   * 4000.
   * @returns {AirfrogError} error
   */
  #fail(error) {
    console.debug(`Closing the connection to Airfrog: ${error.code} ${error.detail ?? ""}`);
    this.#pipe.close(error.code === "INVALID_MESSAGE" ? CLOSE_PROTOCOL_ERROR : void 0, error);
    return error;
  }
  #ended(error) {
    if (this.#closed) {
      return;
    }
    this.#closed = error;
    if (this.#pending) {
      this.#finish("reject", error);
    }
    this.dispatchEvent(new CustomEvent("close", { detail: error }));
  }
};
var Extension = class extends EventTarget {
  #send;
  /**
   * Use `Airfrog.extension()`.
   */
  constructor(send) {
    super();
    this.#send = send;
  }
  /**
   * Sends EXT_CMD with data and waits for the module's reply. Fails with
   * an AirfrogError whose code is the ERROR code, for example NOT_RUNNING,
   * and with TRANSFER_TOO_LARGE for data over schema.js's MAX_TRANSFER_MIN.
   * @param {Uint8Array} data - 0 to MAX_TRANSFER_MIN bytes
   * @param {number} timeoutMs - limits the wait for the reply
   * @returns {Promise<Uint8Array>} the reply, empty if the module didn't set
   *          one
   */
  command(data, timeoutMs) {
    return this.#send(data, timeoutMs);
  }
};
function checkPin(name) {
  if (new TextEncoder().encode(name).length > PIN_NAME_LEN) {
    throw new AirfrogError("PIN_NAME", name);
  }
}

// js/setup/format.js
function boardName(board, boards) {
  if (!board) {
    return VALUES.NONE;
  }
  const b = boards?.find((e) => e.board === board);
  if (!b) {
    return VALUES.BOARD(board.toString(16));
  }
  return b.name ? `${b.target} ${b.name}` : b.target;
}
function firmwareName(firmware) {
  return FIRMWARE[firmware]?.name ?? VALUES.FIRMWARE(firmware);
}
var firmwareNames = {};
function modelName(model) {
  return MODELS[model]?.name ?? firmwareNames[model] ?? VALUES.MODEL(model);
}
function versionText(version, commit = "") {
  const v = /^v/.test(version) ? version : VALUES.VERSION(version);
  return commit ? VALUES.WITH_COMMIT(v, commit) : v;
}

// ui/src/names.js
function describeMcu(targetid) {
  if (!targetid) {
    return VALUES.UNKNOWN;
  }
  return mcuName(targetid) ?? VALUES.TARGET_MCU(targetid.toString(16).padStart(8, "0"));
}
function describeServices(services) {
  const byService = /* @__PURE__ */ new Map();
  for (const { service, operation } of services) {
    if (!byService.has(service)) {
      byService.set(service, []);
    }
    byService.get(service).push(operation);
  }
  return [...byService].map(([service, operations]) => {
    const known = SERVICES[service];
    const name = known?.name ?? VALUES.SERVICE(service);
    const description = known?.description ?? null;
    if (operations.includes(0)) {
      return { text: name, description };
    }
    const ops = operations.map((op) => known?.operations[op] ?? VALUES.OPERATION(op));
    return { text: `${name}: ${ops.join(", ")}`, description };
  });
}

// js/setup/bytes.js
var encoder2 = new TextEncoder();
var decoder2 = new TextDecoder();
var FieldError = class extends Error {
  constructor(what) {
    super(UNRECOGNISED_REPLY);
    this.detail = what;
    this.name = "FieldError";
  }
};
function hex2(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// js/setup/protocol.js
var EMPTY2 = new Uint8Array(0);
function need(fields, p, what) {
  if (!fields) {
    throw new FieldError(`${p.length}-byte ${what}`);
  }
  return fields;
}
function parseHwInfo(p) {
  const f = need(decodeHwInfo(p), p, "GET_HW_INFO response");
  return {
    chip: f.chip,
    chipRev: { major: f.chipRev[0], minor: f.chipRev[1] },
    flash: f.flash,
    psram: f.psram,
    mac: f.mac,
    model: f.model,
    serial: f.serial
  };
}
function parseFwInfo(p) {
  const f = need(decodeFwInfo(p), p, "GET_FW_INFO response");
  return { version: f.version.join("."), bootloader: f.bootloader, wamr: f.wamr.join("."), commit: f.commit ?? "" };
}
function errorText(e) {
  return e?.message ?? String(e);
}

// ui/src/ui/target.js
var CLAIM_MS2 = 5e3;
var RESET_MS = 35e3;
function describeTarget(target, pinMap, boards) {
  const identified = target.identified();
  const responded = Boolean(target.swd & SWD_RESPONDED);
  return {
    mcu: !identified ? VALUES.NONE : responded ? describeMcu(target.targetid) : TARGET_CARD.MCU_NO_RESPONSE,
    firmware: targetState(target).text,
    board: identified && pinMap ? boardName(pinMap.board, boards) : VALUES.NONE
  };
}
function connectedText(target) {
  if (!target.identified()) {
    return TARGET_CARD.IDENTIFYING;
  }
  if (target.firmware) {
    return firmwareName(target.firmware);
  }
  if (target.swd & SWD_RESPONDED) {
    return TARGET_CARD.NO_FIRMWARE(describeMcu(target.targetid));
  }
  return TARGET_CARD.NO_TARGET;
}
var TargetCard = class {
  constructor(ui) {
    this.ui = ui;
    this.airfrog = null;
    this.rows = rows([["connected", TARGET_CARD.CONNECTED]]);
    this.msg = message();
    this.resetButton = button(TARGET_CARD.RESET, () => this.reset());
    this.buttons = h("div", { class: "row actions" }, this.resetButton);
    this.element = card(TARGET_CARD.TITLE, null, this.rows.element, this.buttons, this.msg);
  }
  update(s) {
    if (this.airfrog !== this.ui.session.airfrog) {
      this.airfrog = this.ui.session.airfrog;
      this.msg.say("");
    }
    if (!s.target) {
      return;
    }
    this.rows.values.connected.textContent = connectedText(s.target);
    const identified = s.target.identified();
    this.resetButton.hidden = !identified || !s.target.supports(Service.RESET, Operation.RESET_RESET);
    this.buttons.hidden = this.resetButton.hidden;
    this.resetButton.disabled = this.ui.targetBusy() || !s.connected;
    if (identified && !(s.target.swd & SWD_RESPONDED) && !s.target.firmware && !this.busy) {
      this.msg.say(TARGET_CARD.NO_RESPONSE, "bad");
    } else if (this.msg.textContent === TARGET_CARD.NO_RESPONSE) {
      this.msg.say("");
    }
  }
  async reset() {
    const airfrog = this.ui.session.airfrog;
    this.busy = true;
    this.ui.render();
    this.msg.say(TARGET_CARD.RESETTING);
    try {
      await airfrog.claim(CLAIM_MS2);
      try {
        await airfrog.targetCmd(Service.RESET, Operation.RESET_RESET, new Uint8Array(0), RESET_MS);
      } finally {
        airfrog.release();
      }
      this.msg.say("");
    } catch (e) {
      this.msg.say(TARGET_CARD.RESET_FAILED(errorText(e)), "bad");
    } finally {
      this.busy = false;
      this.ui.render();
    }
  }
};
var TargetView = class {
  constructor() {
    this.rows = rows([
      ["mcu", TARGET_CARD.MCU],
      ["firmware", TARGET_CARD.FIRMWARE],
      ["board", TARGET_CARD.BOARD],
      ["services", TARGET_CARD.SERVICES, TARGET_CARD.SERVICES_TIP]
    ]);
    this.change = h("a", { href: "#board", onclick: (e) => {
      e.preventDefault();
      const board = document.getElementById("board");
      board?.scrollIntoView({ block: "center" });
      board?.focus();
    } }, TARGET_CARD.CHANGE);
    this.services = h("ul", { class: "plain mono" });
    this.rows.values.services.replaceChildren(this.services);
    this.element = card(TARGET_CARD.TITLE, TARGET_CARD.TIP, this.rows.element);
  }
  update(s) {
    if (!s.target) {
      return;
    }
    const d = describeTarget(s.target, s.pinMap, s.boards);
    for (const key of ["mcu", "firmware"]) {
      this.rows.values[key].textContent = d[key];
    }
    this.rows.values.board.replaceChildren(d.board, " ", this.change);
    const services = s.target.identified() ? describeServices(s.target.services) : [];
    this.services.replaceChildren(...services.length ? services.map(({ text, description }) => h("li", {}, text, description ? tip(description) : null)) : [h("li", {}, VALUES.NONE)]);
  }
};

// ui/src/style.js
var CONNECTOR_FONT = "13px system-ui, sans-serif";
var CONNECTOR_NUM_FONT = "13px ui-monospace, monospace";
var UI_CSS = `
.board-render svg { max-width: 100%; height: auto; display: block; margin: 0 auto 16px; }
.board-render .box { fill: none; stroke: var(--highlight); }
.board-render .label { font: 700 24px system-ui, sans-serif; fill: var(--fg); }
.connectors { display: grid; grid-template-columns: max-content max-content; justify-content: center;
              align-items: center; gap: 16px 24px; }
.connector-row { display: contents; }
.connector-row table { justify-self: start; }
.connector-row svg { justify-self: center; max-width: 100%; height: auto; font: ${CONNECTOR_FONT}; fill: var(--fg); }
.connector-row .body { fill: var(--bg); stroke: var(--line); }
.connector-row .pin { fill: var(--muted); }
.connector-row .num { font: ${CONNECTOR_NUM_FONT}; fill: var(--muted); }
.connector-row .name { font-weight: 600; }
@media (max-width: 520px) {
  .connectors { grid-template-columns: max-content; }
  .connector-row svg, .connector-row table { justify-self: center; }
}
dd ul.plain { margin: 0; }
table.exts { width: 100%; }
table.exts td.handle { cursor: grab; color: var(--muted); user-select: none; width: 18px; }
table.exts tr.dragging { opacity: 0.4; }
table.exts td.acts { text-align: right; white-space: nowrap; }
table.exts td.acts button + button { margin-left: 4px; }
button.small { padding: 4px 10px; font-size: 14px; }
.card-head .right { margin-left: auto; }
.muted { color: var(--muted); }
.ver { font-variant-numeric: tabular-nums; white-space: nowrap; }
.drag-note { margin-top: 8px; }
.filters { display: flex; flex-wrap: wrap; gap: 6px 16px; align-items: center; margin: 12px 0; }
.count { color: var(--muted); font-size: 14px; margin-bottom: 4px; }
/* One line is kept for the message so a message doesn't move the rows. */
.add-status { min-height: 1.45em; }
ul.avail { list-style: none; padding: 0; margin: 0; }
ul.avail li { display: flex; gap: 12px; align-items: center; padding: 10px 0; border-bottom: 1px solid var(--line); }
ul.avail .body { flex: 1; min-width: 0; }
ul.avail .acts { white-space: nowrap; }
ul.avail .acts button + button { margin-left: 4px; }
ul.avail .top { display: flex; flex-wrap: wrap; gap: 4px 10px; align-items: baseline; }
ul.avail .name { font-weight: 600; }
ul.avail .desc { color: var(--muted); font-size: 14px; }
.for { font-size: 12px; padding: 1px 8px; border-radius: 999px; border: 1px solid var(--line); color: var(--muted); }
.for.this { border-color: var(--accent); color: var(--accent); }
.ext-pane .msg { margin-bottom: 12px; }
/* In dark mode a frame whose page doesn't declare a dark color-scheme gets an opaque light background.
   connectExtension() posts the page's height, which replaces this one. */
.ext-frame iframe { display: block; width: 100%; height: max(480px, calc(100vh - 200px)); border: 0;
                   color-scheme: light dark; }
`;

// ui/images/airfrog-mini-top.webp
var airfrog_mini_top_default = "data:image/webp;base64,UklGRmJdAABXRUJQVlA4WAoAAAAQAAAAMQEAFAIAQUxQSHQUAAAB8Idt2zI7zf+dj8zMCklwt2LF3d3d+mpdcAlbsffFoQrU24QKTg13QrAK7u5uaRI0Qkiyksx9Xef5R9Yaedaz5rlfJSImAMDq494mFUHpfxuzKlLURpw6TRF18rbI8AvJGEvcpC2x+UxzRVTjeyvdJlNUdY2ZT0UWPqj/DssI839WM1hsoSLs7KsmxBXXu6tjubhiegj5+rHlcWRrxhX5vKOxiVhtPITAMqH093eqTglTFZd66YSjf/iRs0xkXmmck+oAviwrlYrregN5Xq89JY8qWV4f9UZEkfdvD+BAueIpNevnO1840xlRREVYmgdGls/8/5n/h3+aBbOY4qYBadHEpKkPX3z43x6TGElMr319BSy48wQ5Y4jp/GWBNMvTFPgKnfHD9GcgT7BgluMrwRg7nBOXyzIMXsdJCrEj6HDkaDHJRk2Uxw3qg3qClnOMU4gbpruRtpYlO8viRlNnJrU2sGP8OAOxxXQX0sjier8PrefJzxXihsx3T7JWkjR9U17lyCLoejRayXGAuyo8JbJrMp2JWjpIhsWmsMpRnCqxa/S5/wHkA6ZY8jG5qrv505uO/tIc79qCl66JgbeYLFOFD/oKcpyrZvdo6h//jX//0hdPf4RyVbs9agtnxxdBChqcqnhnA/gNQxFECwuaKj69//wx58kVXam4yhBM/7c8zcwYV+IrNfGuO++4c6bYKUYI16sA8Ji8MwwKrGh0dkzOc5df/LezXJ1uSqxklOQdk/TpdHWYfOfw9Y56XxwCHtgBD+yhKE5uip0LkrEzrt0ArPeRs3AuyduiJO+Z6DP2bqx/u6xjItVZ1ysj62kNT8mLRr0zfp7Yhuvl8aaeOeg01LBT6ELHXZMXzeo1PFM453MrYO2n5S2Zzqtjw5fInulQjM62bxZPrkMArDPb1UkGY8eCDsUofFWhFXL6YhiBMQo9kvP2EcA1GgJy3nXZpS+pIy5J3rlvdSr7ds8k6vWTrpNryFIdpKZfdc0MsUPGixbCMk/RW5FpXAN4UN4rySW5hqaF4Oqg+yubAsu/QOuMqDdveUtU665XbrlfVKm6mZWXvGkq1aZORV8d+6tToiRXu5RElWmgFjQvq9Jt6sy8kdVWUuc9uNr3YCo23bthkt64994nJFlvFPRbADhI1rFSNEneOZfG7boQgHUPeVnsiWR+4udW/fp79BKjZr87UR2nbt0WQJoBaFyhZk8kyU2l7vzTqo38LPfOmH4P5FkCIM1TnCvrjVwylplpB6QJ7pd1gt6/cppj0CTLb5b1RCJV5uT7y2Vpnt/VmaDfIUeLGdbod/ZEZW+2DeoZ/toR+oyVk7QV5LhFIQK47l8F+PpsVwddL6PNLPmSLAKImnXHE+psUz9N8jawTRyQS/JOnYZaO7tEAtFMnQ26MMnb2ToWdN71DtrMMUYhbtBnb5akLWXJ/bK4oaDxqLWSYVs3xU73nVAfLEsbz9J7J6e8HOgyFok+czvkeZokSZ4D58rUS1NlSRWbmnkMBl3pSjXVMzsf2Hu178pKwOd/fbWvTiULJEoP/uf6o0Yu/7Xz58jVO1vYDMAfZUMu6AQAP1YokmhSmDr1U0lU70xOWqI+qn6WQgnsVVu4dljBJAuSFIzqpU27A7hJNuRMPwHwB1nBJJJUj01/+9gDbjCVoOvcfc6XK6pSElWN3SyUg8xM1dcCFVkpySOLHh4/Uxy2GEJgr+WzvgSs/KBsuBqQvZXpLuR1rDXLOSw5Pz3k0GNmyHusO2u1JMOb8uFJhwPYbLazt7ofSLF70zQcUx8vVqvVcK+sl5L7T5dbaPSDGq5mrbjAU6VEC4Fl4t6CpBmTPlDBPQRjKSjoeABbBdNw6s6h4JK3YpJYsBIlZ16658/ekneDLIaZWTv9fzvoZ9OcHXBJPgT0+ktqmU4VmvbKuIMumkuWQRGD5IVYkC01dQ6AgxQ6oMnvzhCLZuHcvtpp862FopOzFgFwAq0cGCx4NyibL+8e9af99jtH3trxtZH1FaeR7Zgu7Gus8Aq9WK7JAPCKfKiYrsnqtWzZuWIpdNt13uorjJd3K+jPAPATWQtBP0KK7UJQe5uijn1UuInI63hx6ARdikaeL9Y/HLjOApDdTuuSabe83pcdqNCCfN63ltjubloHdkUj2bNo5PSNgB36XUPW+9cHsFPThwFqjTyvJ0eq2aWgb6HRh39pTdIsiWqPE5ZN0ydk3fNgNpiocO2Vc8ShQ73/z7udMYNU+bu2RaMP3+ma89VFgKWeoLdESq4OUtNefV0FpCT5YEPUQ+Agw6nphgxY5l2yS6JePezoN0W1SQ1u7s6BRBWSmnzq3reKLTAEFo2SxMFoFjgsiHp23O8+FtV1SpKr41TrdO+e6e+LAvip22BDkHrnxHFzxEHK18MCNLYnShJVQA/B1XHqtt233vd9+UCFDPoV+vJ0dL84ZIwXjwS2nO0sJzcNbu3JQ6CGuOtlAPiiW6HOR18tX2YoUeujUccFCqVE6cUz119jzTX3unOmrL0yDPp51siyxeeIxSH/MRLAMTQNoTVreaN2rJpl5Jx0RB8GXvdueQmZbkW9ni7TXyRRzx/5lXGzyaFjOhEA7pWVEMl9kORpmqZZCvxBVj5y2w/AqQwqMjXU6TNP22K7P4sqX3rzi6gnGDjN8CStfOjNS779cFMslDyEwKFU5qZjUEOLOQ5UCQ3XNHcrp3mbp1kryLKnZSVEC8Zhp7RdkxK0nuMUhRKqlEFXImstwzayuNHUaai1s0v8+GHS1laxw/Q0ktby5HiFuEFOXRxJa7iuTBi8gijoh6i1kqYrTCNLwyV5BSGnL4Z8sKSOXyqoPKde/bZYPeT6ax9qaQIkSQZsM8tZFq47l8CiD8iqh1wPbgcgzQEsvPcMUWUZ9EWMwPpzndVDpjljP78YgCVPeEeiSuQINLB6P6uIXJo348ZLH5spOVWezsdXRt/tMlVSBg1orlKlZr7wtqorGYJRZUtJXl3Kmu76b68eAgtEMgJQhaYkVj7qiRtuDmJRpHnz1Su7BS8nctJCwMHyYpAzN15x+bNlPZFLEksp6PxsZANPywphug7AqA/oPRD1j/PHvCGWkWk8gMU/IAvR1E8wIsO76oGcL6wAjLiGVkJiOHbVVY+Vq5D0mWsCXwmu3jfoFDQa2FOlJIkUVVDqw9vvUU8cdFTaqGc7lZVJVGGpXtn1OgCcVFZFDaJJollvJOrq3Xf/NxeHMUoS1UtTwz11+Xq73ifvpWRmNpy5HgWw4gxnLzXcGy9fM+3DY/J4QPcuiZq3Pjbqd0VDl8QuiZr+wzfEaEDNfP11dZ2KicY/rZThBPMuicFjwo7IM9wh61KPTmu6msFLhj57izzLa2MriWtQY6nItC8aGf5SRVwzJ5z5hc3P+O5bkpeK8/F1kBw021k1SP3xcxhw9LcnycpE1Ly7n1X1pOb9O5DmWZrnwGrvystELsmrR+g/DnmKAZMa1vjEvUxEc1XOoGvRSDB4jiNkpVJJbd7uyNBqjidlccP1D7SZJycpxI2gy5OstQxby+JGU6eh1s7O8ePspK1tY4frGSTt/FPsIKcukyQt5cklCnFDQV9H3kqSp8/LI4fz2YVraQt1fF+m2Gm6BciTAdIadphnjB5ynT8ayPM8T4D9PyUVQak3jqhjwTVPkVwR0dkxBemlP11++Z/vbcqpiEh1000DB0XFOd/9lJ2TPIQQjIqMo26VdSFSLje+qrhELycuemdFocp7/sn9qqSmcWusvcUb8jKqqq6XAGCPYKXk1STovLSRZqNnimXUaTeGns50H9I6lpo1jFCS2MvJdTCAsxg0XLpeOGa3sRJ7OFLPn/MCqeGSnLY8gCPNe7hhN+gi9OX56H6xMGRBOLx48GHlYvTV8iUL5JIXwSTncDK8kjNWAnCAmQrrrmK6qqvr5bPPOvxdekHMfrzKqofP9W6Zrtlg9S9PJSuKqCJT02oAHpN1h5y2KIAfK1QVeTOYF2dqX20EHuqapiAfWTtGzSLQjD1YoelztgKWm0jvjiycDuBheQFc1ZeaceONb4nq/p033iOq+9RHt94usRMkq8LAVPddEtV95/hlgIPcO+CSrDIwBFcRLZiKoE3QqOMqWXua+clcsSqUq2vzPKvnByu04+E/F11ylStkvY5baAbn8GL6JjLgflkb1NQUwNLTyJ7GTQOHYcX57i6NlU8Q1d7CWdpIr1LoYWjSxLtPOumcF2bLhxNRmvSpqLb4yeJooPGx2MNIr44ZjQVX/43IkjNzH0ykZGrf9cCyGP1duXpWWv/YEUCS53kCHC5jqbkkcTDJqU5SH//pQ5UvWR5BxyHJEyyY1nGErMxc9x3270+JLXTaJXnpBMm9JFyTRuUpBq/juwrl5byrDiR3y7olBqp8fZ7Ecgg6FjlaTLJFpoilFXQQ+hr4WgFKmP6btVc68DV6GZAfjkDSCnKcr1Bi38KIvuSLwxA1BQD2MisD0wNI0HKW7CYrLeP4FEhflw87QefV62m+eL9YAk2dldTawA4lJtedZ5zxoKhh1/RX1BtYeR7L4XS0tVOZySWJGoZdhwP4lUwlaLoVaTvbl5qs2TQN05eNe1BUGbrea6D1HOcqlNkwTpWn2fZJ1kqSjnpNXkkUgpWF617kSQt1fEFBsdN0KmrpQEkdK7zijB4KOhnIsyzLcmCVu+WKoKZfrogBR3zjFQVFUde0q4/dc5+9xr4iuSJp0KBGRVMGM7Pg+j+PGV1MkscVl4Liquv69Vfb5FV5PHE+NxrAWvPIaBL0YzTSbIk5iiemvyNvYNm5jCdyHQIs/ne64ildt//0PVFRlZJckdUC9b/JG0WPLEPS3Z3VzfXXbdbb6jV5gTxQCxormvPlZQGsOpssjEl6/ulnnm5KoZoFXYVGli08XYUxvfvjLQBg7RPeFVnFnBMXRg4Ux3T5SgCSJAEWOVVkBZPp56Ow0HnzqWK63hmNegoAaQ4cbF7FRE2+/R8qqvvkVZFh0KSOaxSqmFySFSXoWNTQYppuMM8rmdxcBaV/slqatoIMtytUsgK7XkObefJ1Wdxo6pdJ3lqGrePHaai1s0vsCPptkrezdexwvYU28+QwhbhBn7V+kraU4W5Z3FDQtai1kqVbBlfkpNsWqA+W1nGbLHbI+dHGSLIsSdIsB06iKX66Pvx6DQOvN1bOCCKXnjt8hzxb51+ufFOmOEqTNHHifElB0dSNksxcUdWd+l/3GV0YRI8sEiWPKdTc722w9yvyiBI4BsAKr9OjCfVRPc8auFwhnvjsdZPGiPTKiKKgHwDoe1ceT+T829ixd4mKrlRctRBM/3t8oEJsWZBRhf67PT9/oVgsM5L0wGoW9DsA+I68QKQGt0rW1Mm1vjxbUQV26a/HbbbZZpv+++XzZdXsbIxoJBuJhTG9visGXe9GhQrmnLgEgEtlRXG9tTKyPE3TNMuR3CCrXqLe+/nZ94sqKG3STqhj0CxNX5JVL1GFDhqLOlrMsMVcZ/USQ9MKQ/9kjTRtBTkmKFSwQptuQ4qWs+SrsrjR1M+TvA1sHT9OQ62dXWJH0O+SvJ2tYofrbbSZJWNiB/newmnSUo6rFeKGgk5HrZU0WeZDMnLQp62FfLCkhltlip2mv/YhT5MkSdI8xSEyxU/XK5th0MZpnxojiEzTv79VX6PRWP2oF1TlPQQWRi5pypQpU2ZLzupGFZtBAwZXdacmX3jRNLEwEp10qsJTH60E7ERncaq/6Wb0jcCdCjHlDmRYdJI8ntD7j8r7Lpcprr78hqi46hJVSLdgjARyV5ymT77s21c2yYjivjmAUxjiiekm1OvZMv1iNAm6GI0sX3xORKHPXhPAl9wUT10T99j62PfpESXOursxsvxPWppZZKEkMapQH0yY8JgYUegzPg/gLlqhGAJpwSta0Dg06thaLJJpUGcla+rkrJHma6rApOb96ZQNN/jm2Dclr2LOp4EMxykUhtKJ62LA2gEfyiqYXH9YZaEDn5MXxX3a/kCWp2mWJ1j/A3kFEzVrkgps+ibqKQauYYP3nRVMJpkXxvQI6mixhn+WVTHRVVybv3eStYI8f05WxYrsmow2c5yhEDeCrkHWWoZtZHGjqdNQa2fn+PH9pK3tYofpCSRtJPvGDvLjJZC0lOOPChWMIQQWRUFfQd5KmqwwlaxgA7IozvdHI22hgRMVVLmpcOkFF8wWCyLXhFqSJwskWQ07z3NVb9NRAHaZQRZEpgk1IM/zHMAhH4rVy/V2ltcauEdWFJme/fIIAMi2uUmiqthryNN6+vcCyaTJF/76N79+UTKqipsdAGDkFLE4ctfApmpOTT1x1f2vkavQHkIITlX4+ZIrqjLITbGV+t93zWmMK1R0df1tx02PnEyPJ+6vLwXgX8ziSdBP0cjypfrFaGK6HbV6OjqmyP2fARwUXPGU7lecdIPIiBJnacFiSzT0EDyyUJIYVajnfvyTt8WIYnogB0Y9J48nQUehrw9HKhTKQzMEZ1Uz7ZjW6vkXC2Wuga2yTQCAS2XFcemNn59z7rmPmYyVTNTlG6/yXaMK/ND+KRbc8M8SK5kouYrL0PwmgLyW5wnwxUnulUwmBRYm6DTkGQZMa9haFU2iCks+skiWYPAGfqJQ0Qps2hkZWkySJT4k4wb50VJIWkGOSxTihulRJGg5S/aSxY2mvpvU2sD28eM0tLVz7Ai6EWk728YO1xS0mSffU4gbsnBgkrWWviiPHXoKtVZybGuu2Gk6BrVsoKSGz7/q8YOmo4Esz7I8A1adLlf8pOvyzTDgyK+8JFMUpfzGs7fZ+ujvvS9RkdQ0qLuiKS24m1H/j2rGF1eEnUnGFefLf5bFFdNZW84NHlOCPl4cp4pNL2z18a43pX9BVh8zRxH1jX9FDmCNUx575ulnCvly9Xn1ma4+/cxjpyyNHECG4q5WdagN0f0MC6Z5UswsWaf6bJ7kSXfzBMVOsXb12QwZSvUz/33mv8/895n/PvPfZ/77v+wAVlA4IMhIAABwNAGdASoyARUCPp1GnEklpCMhKhUseLATiWZu3X7DEsRL/Mfl33p8o+yv5H+Q/bL2ruT+974B+A/av9++Y7+f2fxsPjr7T9K/jn84v9x/4v897vP7z/u/2K+Aj+x/3b1uekPzF/1L/Qfuh7u3/d/df3o/471BP73/teuK/wfqY+c1/8/26+Ir+3/+X0nP//2dvR39kP936T/mf8T/rvEXzP/HvdHlg9n+bf15/e/472yf1P/g8R/mtqKe2f9zv6oCP0D+zeZ9+B59faj2A/6R/cPU/xGvw3/g9gr+ff5r9pfaT0Z/ZHsK/0L/HdcH0Vf1wO61PXR3WqfUp6hFTEuhP6pa66X8N6U7G9xQa9gFm5ssD0+6UcV0sE9BluBq52BLN9fcfJMaBl2IVGKHaPQnC867/7aC17dkw8FIk30MHii4Om8PAR6RTEcUY/JWmuvPhlFWXL3mRVHeFcbiHkooGXAZVMXFcsOgU46L+LxUzlvUbVtw4KIji3P0ifRhZ5tWDJvOsX4Alf3OnLDLU4oMA9BrdcTMUcMXNqX+JQndqE17IXMQqz/WlEzi849VPeX6SNtdG9M5o8Hyg0sSjeluqaBkXKrIcyyzU4nS59dqbwRFAqTj/VOmitGZdBkPg3W/LMK8YwXn0tl7AInlcwlybEAD7FoFVUu0x6H0XKQcjPg+0x4YGD2XjGrx1ZXvOPUOlKOCS0l/r8pzEhJKnvnLezTHAHih/4ho9T4uw9699dKNhQ4eMqYr2rjjd1KcjBXH8R9gj5r1kup64xYxcocN/68Eb6V50aeCcNDZIfrkUPkH3ZlNrBDJfvVhkFTyW/JG3G8ZHIxKWeYrVdMq+gT6/q/gQi+jC3y0/decISL82kdAf/thaWs8xIu1tKC28ZZdhBBgbiIfty7QTzj+NQjVvmdDVa3WUqgKzoa8jqiXrpiEFMt2x7WcivNlIPvEENrG0MuvISkvo0FhMAg2lL+x4T772D7Wwu3D5zqHTa+eKL4G4gRdE4lEceQY/tOA3ZtQHZOVFQLDmNWw6IX67XRPk1FxRIfSUCuU3elKlapmeeMRICUvbZeA0UosZKaL4ngrpzmNDnTBeMIEHOtivx2CxEW3Y+gyqWIsj9mADo26qPyggURmVKXPVVCtp+bbTjfYsYbPKOeCJkan6tWBmF+ypbPDgZdeE9Jhcs7DQ0LxsQ8tt/Coe1QBUZtkYYUx9Dp899S7/sp2p7hdUDLx138cuhpCU/lhwQBqy+wytUeiaNCkcCth2PI4aR0M7kTaBQiFjsvFcwfOritcnU6Oqm2XdZrzbtpvVUIs5gdIomil+Ul2++tk7tPgCCPLZP56Ffgewo3igspNtsaLy3jAGWG67TaH50MgAGRxciKEklJAryF4wqqbqhcbosb2txNlZDyEHRQ1IUaNM199wJny0xBzQn0WnyYhnK00Y72aB9qrSe1uLAniYfmhFfzvgpf3ryMo6NN1v4Kacc1XXubcMwYAP7mVqBhq6mR3HEkD8bhZoXHAfIG/Icebs1s+mwgh0BbGpw9NkX6EZMwx83HdX8vCDSSB2EpKSSsOPNWXweMZWiq1zXrhsPUjqjPtNC3TEDZcBHf5NbJx18UX1RR4K8JFCFJFXNpnxKJ+nLYtxvy6fKL2h7HSHeapmylWWMWXTiwf6ZWLkg0PIsbFN9W0BTyA/a8E/qmApEzKkNndy2ECLRz7jmmj/zwGHPPzXVXkT+owt0rTp2M1CDH4bvdoDD2aGnEzDk1jGL/8gmBo648x95yDBDlDy+bwfGvduZw+t6OQ7+Fimgi0rL958m6JecNrYc8YzhFSpRDUI+r438df3kweAf+gJ3T3RFtpbFRGGJ3Fni+7g/VL718Pfjrf52niQgK8H1k9jgN39LKHzqT/VJFqIVgZ/6UGM9Vgn8rvYKK5BbnLI+iSYDoeOMzOy49Ls5b9iTuITqtAYzxsMEjDget3HL8uo3OMp5q9LkRzZtJJ/+lq7wYrKSHKDMr+tdB1GUTunHh17AIyc22H1emS7RgC0FFFDm7LyZERhS0Kt2iHJCaP8ffk4JJAAEfTYA+E4QDyZwZJ8TGsJqFDMsPPAoIv/D+fqaDBWI7JNFMPS8HJWjTqVMknTGmWgjcLBPRLNzijp2f7EJrRG4MHP+ak9skETFO5wAYDoRwWz+IEsHpuJGXe6plcR6wl4plVUzjUoz0giHLVQLdgbGN9Xg//zVIvbDIALjrVJ2sv/bl+RzY7rccAMo99XAGmUblFPpaFqTivsrajOHkbElSBH3ZL5ayFrki3wQQs3TVm9OkBintz1GQum9n++w/ABa32NXZjzbOkpGuTQU8K7sSDy8g2kihMTO5ocoKIHxF189ZCNb2j1kZU65rsDRxzAgr44pRudPLdRfUuZEVE3B3RuBJoK5Ur8YQyGqjUnjKlGLsifV2WkmkGyfBUIN9VZQSekX5Aj8CdLIZlMzmNVc/n/EAD5nWj9/O9Datxi96q/A+eANe9heoaxgKlVbumcAIMDgBK5I2zk3YOCWcKNA7w2APi2e3BOPBVyrv5pbJtbozkcS+MbIemfTV7RUAvLdxVa+GPNWo4X+fH9WL/SUfJxf49j9U5T41FjJGzdGNUDaLG5/ipySj0G3Ols3Ik6jvwudITyyG9PCLa/1ocItBSJ3g0MJEggXVxHmtnJM4TOVIc97bICDhvdz+2Tm0HAomJ8R9DcKWeI54C9FP/5o/eDTCttuvy6w5qt+T7SLRwXWbOBs/k+7j9/X4NAMbE2vzS3uN5RechbSlpxf07dMrJbCgdFG4nJBB8/a87amlq4xFblT/l76+U6M56qHg5YmGmBq0/Iv+/1vPC6uO/i7mXB2z7pKT/KPk5xl1CStOadtKWnAlmHEG4xNBbOfE8eaS2xkAUSymRCXRFKt0n75+gV1VkL3xBs9oxltzh6IVtsHUR9hemu0vNB3fxvRTeI4q5+nk4G94bnRvQ77bO7nFUNUKyXv3ijtQo1VxQZmvdTMbhrtEkvs4QPqLcIoB4cmilEnlGrPHtcjoE6F5fK7hOEg58qX8Wwwdq44pQCYNxLK4Bu5P+wy7srUo7ovPq7G3oE4kLah9LoD4zWsWcod4Zs95x+pJNLAcGc5kDHZ2gO4NTbAqOvnHWmPOKWTytERsgYKQWFAwfoTqW7QtwHKhB8gEMetEcwJ+WJmiKI1lAQx60RzAmqEHyEFQMCh9r9twbRBiyb4JstSntDEDoKlV56VZxKvyK5CLIU3vOjkrDvUH9dmQyX/Oddapve49Gn/qdjBq+GmkYmyaaRihy/+gAAP5mKR2L8NB4jd4vh02WUygmL4gyjYO1U3yydLZzC0WuikewwOw7yUXJ8DS/yZNv/ccK1Yv5/VSKVLyahm0GvYfRKSWLF0x6HcYg7K07DnC2+dcKCodc7LVmTWr7g4Md7KUHQIesXdLECf5Rp2or/2fHQ7nIl5jfSnJbcQk0mdIzpQq1V30vCb/iIX5+ssokVEdHmmlaqEUo4rwlILXq4ptOaXhkthISK+hcO9WXx4d1lfWqK+BE9RLBPj23wgxZpKXvNX7Mks2svIABbwfzxo4hVZncFNY0qaB9JfJr/5WdhGo9hDvgQoRJs0tnWBDhmQ2pgllALa/ddTLnBPZ49gjCywacMLp/xpIcgrQCiuhfaJz4ZGccCXweoTgTpGfEBt0oKhrvxvdtuCtJW7y9kvecNVR6yTn5wkpe7Ur3CNVMY8G7KWWsw1Llav0WB5l1davpbpGcrc9ZhJUjNsbWin4DUlgebsuMZZdJ0IFaMqg1k04Ywf24/XHgFkmAC1t4BKQ25YFQTdyBMRj6ZtLOrkEQr0rn7QE282U8bjevhw48LHXUC09/tetIR/37rqGT8T0IoXbOPTT76vNXaJ6Hy6Wc3l+0pHaa3ZvN6v1I4qTrBP420JLdVDGx0bi0yTTPAbDRWrSZ7yWWP/Uytuu0/OW3PyZioLdNmEiF/BD5K/0wKhWuJNFgvHdIdUWgw2pahQ1ebvk+6EetaKqXb1n23CvJ9iY2IXv7hgI0G30IBk89aRQmmQVOqL8HKGx/csUR76RVgi1kYD+BF5f2AygcpRwv9wIdoK+6AjVzCSHWUjIL/3we+7/b+5ecZq472RnEeuUcEU8qe3ud6WDGtdniqxgV/Yw4zsUP/t4GlyM1IHo6ECF9EadLN1or7SHARR/z5yRbu2PsfuNJ6brJuIqUmF1LyNSsFoQY782psgO3M+GD9e7n4qzWY/UdAKIFv0c+Vv1oIa+0MizVW36l12hi0TW0+A/X4Z5Rgdu49r3ZFhXpyA01z2URy9cTx++ov4pWmyRX2/GXBY0awtGvgqGNsXQzjUoWPeMXu3wmQAaX2pwC/tci+jGeg8+Hip2PhsT81ukqvtTyRE1nodNyjY81rHHIDL7XlNWRl3tN6bihIm/WY+JrEkx2WrFAz6/cLlzn0kBa3raln/NQDLknPw4DoWWBD52TkU/La5WeeDtm7dEopespGXMEHPHg3k6XME6YW49nV7k7wGfJS8huV+1bUCpEgu51IgrKuoq9+JqtjA748+ebyfmQomIPQV85rpJoUbgK5wtilm2FCEDzYbzlbU+gvsay2jAIrDeNe2GE/hSXgy9PIhMyGEolRl+WHPmCh0sSaQg7TrZHG23ZfREn69soUuRGiWK0+JO6GaMBYUx72laFW4xAIHnMW79EsMsizbTVUZ95dS2FfAGDmk6PN1rL9bHBR0w21ijsV7UC0wCfv76owobY2v8SjO5lQDE0UMBZU9LU6901n4EbzOF74YcMBGfL2iR9iGLJTqWuYxOK0ytViA18ejMgXX/2rW8kNP5ZMg8XNrkSH/oTN7IIhYJYO+pzhxctQ7OsmkPE53EFtbDaIqnFZGWpmLiQ0C8ezxVrNAM78q7764+g+YZjCWUDHZnD0VyKmsJC2qw5VFyuImrZeTF7AHdsP6Qgqbel99F+giXkC/FzDWoMcIZPi/Mto+vhgqcR+pmzcEHYxPx32gTq40um6W88k0Df/XuuIm/naOs2v8x8t25vOzXOWpU+bLhOCnE1vjtf8iQmyIQd9IVqjX/w72c/HRAb/k9rpk8+X6ej0Ldwgn8+y9iCp1090BjWiEsN7rMxCkbZF+83UonPJfE1frfnPIunmsL/NI3Ba8wrnI1OrT5+Xm3oKnM4Bbk94shFDpdKzhFiiixWVeQWJjUlgWWJG1mY11h95kqb2ozXiqNUrSfuMF2Vvo6l5vl3X4sTBkycAAl/sKwJTiO2nIIQyTONHMQ7nHBR9bOXjBcle3lyBOgOpCV99sxyC+svDuD5IFtoTBhI7kOVKJ1mgHVa9qUvAsvW1trgcH1/yT4Gai9fD9wAloR/U5A1KbxlAVmbYnvSk9v46WV5Id7MV2jjJQ+dm0OtDqsmjDWPcrc4cLys+fwm/0u9ABB+NxgWZE93eWWjBxuemLi/TlSHWwE6rKVFU12sdtnYJEd9ZU/hp3VgaHWhdEymIy29+9Zj95KyCxRJsluBdtg/a5v91xu2bkF0r3/WWv5ytmUd6sAVnBApK3tJmIyvrfcAUisIMB9afsHshBIs1lbSy589f0XtfYD6aPJeGk00/6CRQXtvS+fRPoJOdDkCZLUInsa22trbsHFx9GEshlSO6iItvamUWlcV028FS8/WrqsU4a1tU7zy4ZYOqQ5DA9AIQN0nkP6/Fw5usjbVcufjYorsC79vnpchh4vi/c7NL3OPnaUCyFbPDy6TsGpVDaExyIj93E6F4vJc53UkMY8mQpckDGYFqVWoZKWZ/M3rTi44KW+XxaCCbORzZRD/chM0tNecDT+FRpe5jW/w/7dkjtpMwPvOlSw0YzqOvxDm2stLJXR9/1u7q+O4fDS8FqMzEIieHgzwBq3Iki3F3NOZBo0Z3Mlr9+ZbC8wSuUDlOh50i/9oIkHZIzwOEokXJlcmj6fWbDrnUD7pUBVyPzQXms/qixPBZmgxpGXlAy+zAIsKEnRNk0B0bQ86Ul/EeqPkIxYFs9UlGrOb1/LeX9QVxa9V4SFwnGSh8ukk8AOF9kRkR4E1wy595/tGqqE65lM4a87DxHu+A6qgH6GB74DMaFr9V2b4hoUJgoAmTpRufhZEJmI0n/hHVE5Tya9MTQq8gHp38OxKXnize6JqqMOrQH57v4iCLJKSMi24IhKPjbPH4zrq0FH7oEp46bQZ3xfIj3vCl05RcZi4XQUSkbum81sz/nmfjLzGWyACn04noOYeFWUsZGvjbnv7qqByRdIcom/SHjB4dNNrTQ67mvYiQBNjta6adoIKK16NrD+psb+t/Haxz8kjKdSSx1iNovFMvoIes1bjAa3ZX69gP1PgIYRpkADRtiAdU70m00LMzQV/19YNKY1aist6xAJm/bPX+TGCcZ8P+n14C2WtwUbSTLHqyMo/3mUrNVzAan5ozBpVmgyLCrgaaQYPkirY0VcSs/cVgmLvRXiJLv5X/hifl9Tj/klQOcvSio/rOAZPt8nv5ggwspo629ClhTteAI+/a1Xw5kVHgJG0YM1HvbFhypAz6Z/CNpXAdtr/cR+jJ9747sU+ukKxoyAVFB0eMHa/0dNgHamDaPoA5kz3VCNjK+5TZrmlsH/mI4CllCjK4cqqShHzL3ymnkVzYh1f9RMabejxVvczKuTMVfljkrqH1sSfgKURWUFaybnbe8i3H5DaZ/aVRD+kegBf1yAidEj36McWlF6Gaw/7nASkbxnL8q7pJPk315tw9UqI77878RrgPt/eYMrsSiZu+69HRP7lamnE7XJ+7/f1KMbZvF6hs5bMJOB/DuPexQbN3DEEdnZlSYcUZGtEsD6ygxgq5FOVyLj0uMHWRJiosgfcoCAkNNaBmA6kRB8OFaA/Pre8MHfBHQrYv60ZfIBzdr0dG/HkPDN/1zWceTFOaKMjXUfGzR2k4fkFBQvmaC+XQYzXAqxegvnLkHllzOzvKXDlXPKnI3Y67+vs9jNCjW7jUe0Wl6vkQc4MdWhySN7QnLA9NtKFH/Rgkq+iWfnxZwQkhyd53WMOJQcmWQBH1iX/IZ0H5h09RUUXPuqO2K24PpIRp4JA9PC6UvWpcvOwU8pDBo2B67yLWA3qNGKICHNEnUkt03WW0S8CRzGi1zHnuEHDLQ4SByNK/vwxnMUwK+GMKCBkGhoOHmYv3dW7vYZrXzn0GpW4D8Zt3sTXOPE8cRBPjq51Irv3hBCqkc59Db6g3LzeNQeSzzsbdJIqk25bG8kUHsFe0Jr7LnjCpMpt7SaLb83WNZbRmDDAHxLsv7Y8M/HDimukKKm4cqIk/4fqytZS09EkoidTzDBRZr6xdFp17aWIuLTiORYaGCR9TPNGiKXUyrNR0p93zT5OmdtuhPZmmTFNmStObZ/eHmKIyYxI9IIgde61Jgx6Zum+ZDhh7dRvjB4AQ+XPXupbco4YiM6KW+oTu41G2R32bBrGM2lkafXYiORQGyhED7Vb3nYlJ9WiizavAyPXsPoHdgR+7Bt04SNZEENo/dORLRytMjwSJ7olNGhV54KoXjuyd+UrVrfdaY1y4YMpI6g6CQ1SPG0s+cYn2ePm7tL1zPIlrcpOybKnZ/93q+rso6ZqHDcSCf7Ben1BrsKuUcauI+VwYC+nYth+b5CpAXvtx9uqVo/XZ/CpcGd7fSt+DLzLw8PscryGe+TD9EdJnzoGmyGVSmmC6wOi5/bfuBYeh8YSp0BmBXLqifMM96chsAZGK3gP6PXKk1d1LC8bO+kUE2puh3FDszhlZ6lOt+VYwF3ZhFup1/c4Jk5d/9pfd/rMDTNf9b9wUL88x6FEJCNY0u0FvzP9Js789j8pkeBULxy4knanYoFwstqRHWF4FD+aLj6O35k6nAJ+4tNc2j757v7XSkeYYo2+D/iwDDyK4yLi2QolcDr1SRoHuXZ+TYuxCxw6qoDigUGxZTmijNoeZowp49XOwnGglC9fhWTCo0iCn+uEdKcFEbeVS7UxqusefQUYLjYgv4qx0EXfvaxUX2O7Id8TDWiawwSJQ7F7ewXQlQ6BGBjF/7cmlvck09DfDGPoMXNnc2BnSgN+4lAjHhqisfyLN6E1U3SG3vpgRXXIXe7v2Fp+2jhQsDP9d4gO5w00kTrA2DDYaC8Ofc+kgIKaYSeM17b5B6OCEg/1bv9Bu7hyLcaNVGimbenuYbYVp7sV3FCe7uhbvuWC4Kz/MayZiBlpwqehfJPTvh9gDblMLXCsP3sTJ2TS8tqVROKrTYDftNy/KvJABV3spW5Ui9XvCHn1zIeEbMst4bOIwgVrlV/2o4AaaQrv+jMeLfkEtRONDvTv5SaNT2FIu3IpQnKssW/vQGVf1wUeGZJqA87BocZTROm/UAIbimtknahmwUvO14YUH6PVjIyUVdL2I6vmW2Dng0C4sHlXa/y3xvgj/O3+LsJFHQY338EldIVWBGD4ZYN1ukzXBuuCit8YTa+M9LIq5T3b6ghPVTy1Z41B9KU9vQQlmEgDOdTTYCpNKW1hTikeO24og8za2d3R2gASxwhy1tD83tPZVDlsmQ6tvbvQIDzYkkppNuk2bZddRzfZLLrTyt7FV33yj9TA/oIoq5QbJaSnNfBCkbKglgvtG1WBMOfv9IU5QH40TX1dieFPTjzxUGMUtkmF26yT+0ziqtbzrYa/G7h6orsgksabdQ9usL4qtdhnB1T6B3bBsDPk9wagDoRvwg0vaEzgwJiChPaib4+MO5n4hh7RqTOwAtDLZb1B80EbLuoBGPNXt9UmYW7NnWgP7OiLipV7waJnzxXAkDrboXMjDn+l8faixDozhNBLL01AmSAgkJGaNm3hjIc1MJOGLsF4xtnOZZVPabhYWzQKGxhC/rpesF4HiIrwFiFgCwHx3trG92qdg1Dc3w/F7n4GyzwpTxCXmu/Mbw+VQdKYo2edgyOjcOCC4a4EKuxgHH1ur4GViNHrlKh1+dpmzgJC45HqwsZA37BEST+M2LRnuRJJFAVjhtYuoB5dXkhhzPcENmPbtCzoJEf59MAtbKbzkEPLuOUiSdnLLSSVoEm2sklgBRh3UhhvItMh9YvNocIzBZUwCsHD3n+gu+LqBzQYwxomovh5G8Wyc4XcG/RiyGWpyQG6ndxbOYRBz0TAo5g4JmPI2ztoojb3cqaYfdM0ABC+tDZ6CZb9qVuglCpVK4LRLIvdB9fU8FDzFRPKJ3ITzoJOJQW521LihQOWHofczZNa6aa+Jt4PiXJeB5Rdh88SPhhUD7QoMqiWlX5pc0lEf66AaOtn/v/WEm9ActXtLEoc4tvWNDDianiVnN8lSEtbGq8GaWQEWPszC4ifAIcHyHZEvSqLYeAR+n1BhL6qJwfcg2y4cZj2xOGDsSzf3VTUsN6uimHcVdm90WF4bzBKNXxPPNbiIhQcWODRra1Ungg4wy52/4tMpsr6v/2h/Ijt+yXANLN0AaijyxLgQBcix0YocBWKgc3q5O9shDiWS9YqQirCYhTR5jK8q6Zoc/FiFIpw0Qa2w3Zt82FkoLWr476neSSKM5AxUEd8jmPj6vt+UZK8Lg7wuhAcgVY60C4a9BCWhfvUWGq5C+u1fWNp2S5hKBzaLH6e0QwS6eHlNfHwOyYLpTXBbTZScfueZmPYQuAQ/BcmkKUTx9CA0y8QEjT65Mtog7wcCNk40R3aByWwkfF6jtmQC7uYRkUNXmY3vJwu3rUzggHzX+JgIGnOt//CN+tlhxrZSPfZbgzK0KLt4XvBqkiwDIdfT8eGO6OH1/tayVB46+CJud1KDRhKogNqz72MPaSmplBP5OQmH/8iOXIwpyWYQclsRozDLHkQC/1+aIHiGroaRxT4OuQYnA0989NKx2F2a/8FnOZksUC0nFZX86M4OQBU+WRe9B2FaStzdCsTbAkLQL/SBT4Fsc8w97XbRYABc362pb+lFyuzqOEzccQTlQXzuRLLpIQPVjYiG7U1LEf9tWBH3l+Jg5X78c88Z5y888rqXKUUXJ4Wenrir/WQY95oBNcrb7MH/Ktcmp/0wlxy6zVqO93PJN4oRIKZ9OkVyAwVsvpIFSVX+gZt8tBAd3MgRsfzOSHBjZ8wKBfJmw0RXtGVoj4iOSJ7XTl0jRUvkD0MLSPnRNJOlw6AdkoSnMBE5DlXWPezGPK1LNiO5hARPLK1n5Jrh4h9UF3sir102rozITsQfukPRZpKmwU6giE20M2sHC82fAdK99cYJfKM1XFQfrB62SCZ5eNdnG2hyc0/GFfd3HYsNoCyVOkWWcqB0f+a2pp/+UTI43dI8aJiJjwVGywn1oCj9EwGAHO0GA6IA98pydxR+d8Y3uMI1wl+alnNBQF0scmIBoxo0Ko2cwec7EehNUBI3UAUpwCDoCJTm8hPtkg500NAojaD58kRfQGOf3FryV+setKsWvbLBl0R7cIIAtOWvShYBqVjL7GEHB7Q849IJyJoIbMwNiMhB+pWPT9/zavORheHkUgfyahx+cY5b61A0Xe1fzhz/CTelt2pSOIJVdsV4hHAuJ/6WuOuBj048n8iL/qZY1CqUbzVQJJQQwt2G683fqJN3XU9l2Ly/4uQK3epqWNIVyRxWB3dalK/v2mKWgncAfbmuFJTltkEZtjbOjNfwhovFmq/GIDUhImaBsz6qmr88Nuk3JcRIJJa73WgMS4M4Pudrtq7ikVj5aebLXmMGtzw3QlkBPsyYljpFqRSh2I31d3tn+p2lQL2PwmofIcHq/l+21GImyZaOAM2ANh66qeu9pTQXnswL1JiORaIE/veYafpHkpP7MpxRqiMceSZkHyGQnpaIc9KuD3zroDWzjzi9D66t7/6m//5qvHkgfmEZpW8Nn/8G0O0CVwrlEsXX4AhzZHOBjdO5Xm6hWQILG8PoDgqrMzN8u92VGO3yUfggfTeYnsOzcdKcoybrXqxIvQlGz+CyRo9zh7Qj4R/71NT2KqSyZKR5O2C4n/CtfwFpjtvnnVyVp6A4SKuZdn+1wyuse6p0ivuJMOtxAyWaDz/2b5adZGATZU0lOm0DI0v2VGHoKrenW3PnAwWxMbQrPOTt1czAYDNFeOVTg3YKMVNcyd931fqdj0G0vKLKxCxJstVSPnZp8CJU/tKSxRA5eJm+Y4ArOnrfR9hYs5cQzZLz+CYmrLTTv3uEGzciuKXofx0DaTOTVlONd0uPVAe5TTBpE+iDUtgYeT3jyBQL8mG3UtQyl+9AwDbHcL4wedRZ7HkP3DQeSN+cTYg+qrHds410SusaVJtqdsvXzVOvRvfcPiBN/98F+DjX9HGC8cdIBFacvdL0zLUWYz6Iweix+2IYuE+/fxXYyNW5uBKPPg1RQ0V1DU18oNErzZNPbY8ECENCmWMXtcQkS+jmnBa0dF5MgINSCscMg0IBjYd8kcoFdoUDvT/Nev6VEW+PsRfJs6EMv7D25gNN2QQjFUaeluuPJE2yigddUTZ8qySrpydonEyy8YjIcvXo/X0TmfdLnCiyOar7ghx0HPfPcBuxMfAQnHUePf1xqY4ucwDcEN35kKunb/Scwp58qg1rj4wm6EqijJO7Rhq+Z9ZF6p0Os9kfo8C3Fglzv4AbsTcZPv1iMsgqxlDYvzFyep5/pKLftVdOlvT9t6Zck8CrW0H4C5XszgteWUEGR9g8NjWq0PiY2HU0lfMf581YD5diVc/38rKBxGg1eNNH4szORpLQ8B+9+TcDERpI8juXWQjgTKzP+HDDY5qU+pxp1pU3KO9sWMJBB1NVaIAyBOcQwsRQbHduk52oaK3wzBwBnrTtRUI4NtxaArrZGXw/FwgDlzXP06VRpCQQHP3FRurk3EeTl8a4J1k/jWHX1WwN/8P+Jo1RCzIVn9I0I7KdyZVHuegd5dE3450iqem9JxrocGFJTzvw323/HiWkN/kQ1wW2a72W3asGeP519IxXERGWSUTI/mucWnZt98IC24lRBuHrr4SBr9LYrmnRaMisnnzFgJ6kAvM99ZgbicoS3biNIHtkOs0+DbW9a2CqnZTIJDodGBLVuRf2dJzKGILR5RPxkTq3HaLqsSx83PH85SwfvOmrjLu6Eokej3gnoTEjmavmUvrqQew4jy4B/Y7a78EOzDSscReu9biSIp+xw6H6gcO5gM2aXE2QwtjhEd4OTRw7uhKJLkvahUxOxnadiOLnLbWWSiWozsIb41c2Ac7pc4yBxm9ecEg2MuE/Kw4j5tVhxmfe9PvoeEA7iE8oLE4AvhqKRspUT2BRVPC2Sy0mEztpGB0OraaXie+LrKSm+7Vq5reJl/5tXEtfkz51hO7zGfAwwOLGeAynxFOg4pwHPLvavA4Rif0eA0Yhxws2cgxkzoh4dfR0sjqhzSVujGSYyzBJft9U6JmYllhVI2LS1lsgkoR4Kcvmpj/6zlLkvXZmSfhhDohKO1Y7mvrnuVUQO8qpnDnkrnNXtVVB0vJsFeMH0h4U0n1Zbad+MhFUkTits9G9JGYSsdIZvX4VwgVpSOCwKKDU3qY9eVRS1S91Q/0wg6CC264AIQsnjEJV2b1tsBay/zLVL785UY5q42kiPMyxhcBoSApw1iuzgdBg67sIVX/F5OwgqzXRcLyDqWpR20b70SCHoXtV2pTjK4bjO/Aw5NJgcCK1nIcTnTNk+guUbplc2ys6BorBR2pT1h/WGwg1R5oiEJ5jt3sspZN8w27dvbs8ceDyNik4PraJyIvldhBmnSUSxZp1ugFKtP5u81JDk5dqAIti9M+XWxtwTqyLECtD3DnVX0NQwyNtBInYZZ97p7RPIIaqCR7VArqh0bCGIfyArvQx/p293O1X0ODPp8604eYjkwoMuO+gzS8Jgq8VAtb4tTvSMzUgKMOGOZyRqMY8uJHx7/CJGEHBGPYYCa9IExkkmLrsI76AkGfRpL9AboQk72bR5OhXpsfCh6sqBhL7U0o3f0DYw3vsCdQ3nBpJF4ttxCXU0PfJeLhzOcjeNBNzvPUzt0uoVdZytO0LAefE2IZRMi/5oQ39JnaahsxfiqI53AttuTApCwGVRpeoBqXoIt+mFJPRSUg2nffsT3icKm5PqIx60nCITWdL2UMsm/XAxrQACb59F9s1bE+N+U4lbarrhdZ7kUQHIyBdw+r/T+Gc8OVNYNTTZtvM1yB3sVys0eIWUDfxiWh6ZKO7Nf0zRGgMRJ7loMfJLxn73tjO2nHGNaKlESLJQw6YsXieZB6At2qDfW2rz2heahFEAQY/X1PlE67HQX60I9/eRGiem9ahJ/5lINJgnw0L6NPjY5d47GY9PlZ7xcskQK0qZWz2iCd2rqN5efUm6NKO40Pvhs4oMKYBW1xF0cZZIEEiBDfYiXDD3dO0dg5WV/osyDhIUyJrj0mQkUbEj2hURgeX8wDZHIoeySWb/n80KgHSnS8VVpsrdd/5AniZBj7NBrl5t2CUvaqh1jccRZNdIjRiIewBNT9X1bBJ3Omo5gxxeVvs/is3065KkkSLoKlI+uqBmfLYtjUXkQTnevTbrTGr9gz2W0jiq3TUqb7nj5AXS9xipgDf0Ev62gSuziq+Cm+x7syL2O7I5EuD9fOM8BdQoVPRFbdS/rhgkmynN+qZrVRbUI8sPTCz3JTbne9QqtzEqldyt76rV82osgFBWVs/8zaQiC76Yr+b23/AvX8nMIoBjIkL9Ufec40G/V71yM5JxmBY9mXvOlBNo7aWixkeDgVCm8vvjqjKZs+bRFb1Nk+1awY02rdWGlNC+4Dyrnb4wTA1nR6CL9/ln2ltpxedyUSbjB30mXsjF16LDEQ5zeRy3PnmIHQaL7IuKeARdkr+gImyjaMIecEtzLBoBOvOeWAl+ubPMO/X0iYLNLx40R2W/khHyTwRY6VahJrySpmS/ODf0GcI7OiraSqqxl3SYwgZ0gCJZrtyixCxFPHbZHy2eXBoBMarjPiR6zRh5D9xDMJFpeW0qMaDpWo1a6DywowTQZCyFllp5xHoXHv3E68XHp9AuF0L99+c+lozMyUQdqEORv4nYJAK1ZRct7psPhadARXGu3XYjELv1rKsl0IIOIAYDDYGc+MxeuCnGCLwbC103NTKq1aMCzMCqPjNFAW+88CRjBMJHGo29jwMmP5WQgwIk3nC54BKtf/V0gGr5zIid8ALvo3kismTIkkSF/WEQe03awbEidwvN5jfODqW9uNfw1XtCmFBP1hbMN6sbPRVHZQZ/Kwl7iqZSodBELpFgk0u8SgL66sh9Vep3bmXejqsJ73MkNMGDcA6lM2sT+ktqwJAxV3ukHrq3wlong4PhrD5z/1bht6nCRQkrxsP8xvWBMpZroHokDuKHNr0Sq41DZ2nHclzRS2J66lhF2LJHkQxB5w9UAU2j2h23SCiwdWDmlsBg9g2XF2XB2cLtTvTB4tZ1xXGf8bjk1sISqIdJPFL/vXiAmPCNj/M0QFsuWstMTQjci3K3D0Qs1qOgxkwUXw6XwkHdhvVcHHlGfhLLm2q5kP8R742x9Dcwd18DBsGPOFruw69MJriWBr1VQWIYk+jhpwbxv3ljdaoMCttLoC7rl0BaSZXITpGebGLMJONC7iW1CQQ/mOChl1nsAks9YlCVNrzK5v/daL6npPKknQzQ6D3SIYZwwLmLYNv9LVE+SBkMer1mDHd4QhSe6yBIvz8lO7+7+Xt6RXk4L1agAt14mXRf6KoOms7klihAzWgDNQppWI/zuZ5rCDwo9YmQW3U3fyVBjxB6tmy1HuXj5zcY1rqEg4VYWmPjqJQwj7atvVbx5NDLTaY4i4O+XbHYEFH8wwYpz/S5fI7fkQY9Jag718Bv+rOTPYtHwtqVnMMNmW5LEF+V+aA6ZP6lmwaGT8meqxXvqMdSbf9L2xH58tNNxvxN3bVaYUw340raMalGGLjSQ93fx+Lt9Mr7eljZyejwMQiw3nRwMxzE+kjDmfdcgkw1bfrZ3gwBz1Y20Qa6zGiFF3MoXlLq513ZdtBxIt0XJxfEPkw61hMtFPF16lLxzGs/hMnvkul//9tAjkxe25nUsDHvwnSyiQ2CO6SUqEzhzqeob+GUNiHtpwdxsaV4q7Xe+GaUVdeYrJeSLXjmSMPYYRiKj9LG8MvC+hT75a8t7oUas0dVUe5OsUJuE5dzGP4dDUAiL3UVet7HbBsa8I5Kp1WYgeVknoJ6lGf62EVgsB1KZoJxN1vkCItp3Q8IIUTfS6K57C9S8ksLTaeb1qeElvRMhaPmiSu4aCwPjINJgXNl2lhUAW/bk8fUTY7KW+pwJQcUDOMv0LrLB48wL2MFUy/KUqLBphYmpIOEy1Qs/W1DyZAukbDVnOYyc/OIBXl//flxGSyQ9ck62Dl5P1PJhKDbFY+UUDfa/pRDtUyoiQSoiK6fjYWgSFB2+IeSq4V/cJ8bq1QmSaHi7OuG2j29WutEj8+si0t60+hMzw0McIASaCdV3agPD3vnSZM/QXhgqVWHIJ08rWYNfpeHJ+OjEMfmF0Ad5TyzRZoHWOGXBUhnuJ9dw5baltyilLMcJC74lMtgqSygt3F+Mj49H90Qulve1BAj9k/Zxghs8pdz9rn3NAW90joKKsIs69IcDsCJaOw9weRF7ad1wR50SRkzaOv8q74nxM4jTvT3u0Fi+drSuR2QwcUiu9na6uOvQ2iLf2nHDVlND9aWhtQEiUshltxX4PXruRbV7XeyhbygueYphOE3pO+B3yQWxEFFrQnhuEtM8nTV2V4Fs9iLZcC+2bxeqUF5PC9R6U72FxNiQoKqX06guoetxhUVqOxim6Z/lOkVNXo3RZtGYrhRLB+V7ny8UhLB1H3Lf4XE7IV7pKQFBfv90daud94s6X3zHNb6dpqoe9tFHuvAGwriyLMaZB7fScRR42OAnpQ7U+Z4kDhK+9+2pZbS7R3ffEHEcb+EjPPAhyXBd2S3TiwAQTovSXxdgKaBSwwoQ6BBmmSfITC+Wbn9nBthzHA4S4CBUUoKfUo35i6kaxWlZu25DSonxus8LOW594G1LvYDwB1dOOnqgadgD8oc/9Iu+9/nt9LpMOcGgmQFNijNCuIxmpCU1snGucxJfSA3FsAv0hKQfF+0NFPAXnf1ZkYyUc+9ESYLJPH3NYDKCBuxGSLnMwK6eKjWCyIE29J5MSZuzMYHZneHVcdnwoZ9R5Qu03ZymWo7PzVuDWoT97qjllwBnxAjp/8uRobDAPpmgu56spwbhjfxFGV8q6YJ3UK/Im7qnjAk0j1mNNeHOyoGSGNKl1fuoD7VuF2DGiISSy8O68rMT2XnJ2/I9ZtKrrJN4jS7LmoXvmqYPYs6jQ0pCYz3q5MBN3zBf1YxsmMaRg42nnjpJjJ6wcdkP52CYw/pOXFW7R4AM/NQvJZFsO93u2pcrcoqOOxuZZT7RQ101aAn2mxkVgX2BC8TOtmz/X19xlP/aN/L5x75qRtPjXPM1ujss/lqss35YYjfmFwTlgCQ0AMGDH7KHTSW8DUGbKbUuiqJ79FBeUf+ksw0xnqvqD4kNouq3tvv/vsULVdRYLN8nDqsEwLEd78PujXb9Rw5dWXI8KOSFtdmbs5/5bBhMBlfBW0WSwj/q10Y7ommXMaScKB9HxGEAiAO4kGOgmBGfoaRtoj8e2p5pzc+KI8Nw6P2Q6XpqtdHHamLGDH65X24nvEhKFxI6rMJIvfrsJr7wok3To1dxM+XwKpqXTGUGu2nUlaCxr0d+yMevEI/fsb99YxvPrqj0sqJR4R4wqaZqYOO0GfHHB1vqN6SZBewfL5U1FfZ7svIdxFXU+D9pMCiXaQt7a/px/nQu3AshOBaKFnJYo+AioIgIh2gT+7Gqc9LQIFhyXwCPXbKD4VgefxUxdeywZs2K2ivbirYlOjurw3zWjACxRfZdQ12OFYV2B0YWzBVLyp2iFBXLG3T72jHA04EFmwnANpa5BSFiRDVo0WwE4MIDaSWs6qGFGQIJvNr6WA3nb1TIEru5dpufWYnAZvg66pLgS2lw9Y0v8zY0Fh0JPr/pzp8OoUY0P4qIWHdgfmnZFAQlgG/uB745Jabul4m+rgDs/7KDO1iiYR3Pg5Yjbp6Sz1zI6SPvt6FZxlRAd/6x54v4bc9hK37ejp2b9gQvXgwwEbZqJ3yZAbTWJOcRYtgA7yLWJH7myerkj2g1ivLoJyHBGoiY5UNjKNlHorZuqTQpnIZ9mxwtFl/688Qi1ZX9GHiAe7TnCpq3J6Ee371C1JrQATK2TACLl99fVxjQSWkvJmRRB502Ij6LcPA5CTZa0zU0R7soas4dPPPkmU8hzouPcdjW0EdhWn2+BbyLXXYzpwXMBmduA/wDMXQyfmHcV1/wPC/bdDvHXnp3I+kPfFb9z4N71C9biB7o1Y1fkI2rMVfX8pOf49NpdQP96xnPUYF6NTbr+nld4Iw1jSw9UktyRaI/+6wKXfuX/jNh+GyEcNaX77c98xl0b8gDK44171apusIjM4Tx/80iTLFcqpsYNJ2M1D+zO4CNuvE9T2oPXTogerLY/Cz2S+JoLzdLyKqnJ8SD53rFUAeyJYtxJJWVRIUx9ELjbCn/pBcZn/Po62kQcrJrF+mky9yVe6zyoECWVRtuUJ2PmwSDfA+pVoV5voZ4EdOQyV0yCQEgzD/8/HWcZXkGHPzts0eSN8565w/0j/k90GkmrzWD+Nx7t4kNrdmarZ+/1cJaKee7OZqsq0IjPZ39SpBmruNvL+8x3FN5baFW2yUOQjWTtK0jUst/CMjnPXoZxcON9oCluWclL9Ev5w4hpZeAE5/1TmI2O4vUm1ifudPe8qZeeeGx5w/dg0iJFEjXtLDgecvuafEdAEuZelh9UnXl1UwJx6mMTloyn4GN1/306fRHsY6Gqu+3rPDTyiiOc22IXGttuPaFULd6hmxuqyoTlbwx1a01Ob3lKzc6CpUJGjOr+kHLZ/mCSbuxwcrmdoPoku6LgdQoERUFvyOEpZAlWXjSRRJHtd4FoyAcDNdYwP332mbmfFFfDdOCfRk2puGkqoMmcGYDzon+mUNdRNdE7t5nfGFE1Y/rsHNiDt2JzUzUh9Ak1u0zYxxkSY7v0U8B+w4n8wCm3nXFtxBpf4Xh7qp+ah8jEy0BBLNriJPATZGpXJmblO2n+HfRM7wxhy2Wix0Sdk5bNVclz1oAxEVqhMHLaZCtp2ZoA6r7Dx3iP3xUJFnJ9y/45KVYeUdM5LU4FqNX+e8P1EaUO9zOF3LGSc2BXg+Ds5nFsQuAVW89PRE1VtNMI6nQwujZ0Vg67ExFgBdYxsWDo8C/kiYeJ6Bd6W7GJSvkoCoZ8zwsiCLz3Fgnj9f6Nag5urPfBBAnT+0iuFLBbS2utNfSmX1dINDous0TS7Xvrv9i9oXjKkG0/nKqXFqDGN2NxBua6jhipp4KDE1/fbVq6lUOrqabs7Hu9dQY6gqBbJbCciPMMpMFA9mGLRmdJc5zTpxgsb406kS3OVm1dygaddhkM+Xwuo3lTwR252gbTmdzAIXsbXo772bDiQ26u5CZ/wzW8AfCU1CqhByeEpLuzAQjF3H5en3jV2exd/+Jm2+1aPLS2UYs+armIsPaVOaUOxrcQ0wGp6pn/c7kMQhJXYOpL2+HxK3uLqwoACPsqDTMpSO3684LIFiyzigWqyPiXT0LsmdIom6UeWUdeUJrDw+70oVYGGkfeILBxeZoMQYr+qMx2cbIUi+/DqxzTxCy2O5yioaDYURNVbSfeqZUKHSGnnDhqhHF6D0RMN/RmqWSnqezmX+CLCBACPar9ixaaawL/lORgRyaAtJUNv7TT22+DnGgd5eLviA6xse3uwWzBrGVKsU80bNF5JAeDd8BQm+rrpzcBlmFIUVlhNFsFs2zoa4e++ckNqNQzyikPHg0lhmLlTmBc+yN/QFpazTMS3Ku/M4B41wgD1jVGfd+dgSqnjcNdfBxPhCEq4BI50wZ3w4QBRRoMGnQxAlH069olbAJA6QNWKeKI8LAsQt73gVUWYxYaKXIR70rqVzU6mRYgqL8JXkz1hi+fkLl6q/ho5Nv2RHJP1MU3ki0iunPgSTo3z6O5K3upwHG7Cg5tmy+Jei88B776cu70sIjQ0yF6u/otOjGRBzbFs1qnJoyEHXD4yvkZTQcom272R7VSwyGPYXT79qGObEnwipaWySZt2jj78WlHDB20+iGi1Fo+Av3do6plZH556eaq3iaoRXKanWQ8phvZzC0yYCCZNK7sQ8w9wu19O+sopgISsZ+mHL594V4GuNSidOgoFkTP6g/bEo0aoup7DbY61Thisz+OQoUtGHY2WccYWhyIjZ/Rh6jcWRqDEayG00cUzOJulwN6AlOQghXZIvqjicgspz7llkJAhLWflAoodIQ96CWGWh50SnUGBixJw9Mva3Or7e0FbIb0o8WMRWyuehRtfsaOdWheny66jCNfHZJlbBiUxHlmGRvCpklLpzo1IaPYm9Nfina/Gt24vFgMCgBTwTjK7W4T3dJSrV1fo3o/VgfI6XOXQJg9g+GVW/jJj5P7jqciqcTNVa6z+9AEBV5HqMrZktEcpSThyPc+OR6qRa5s9BR+/fkAvtktmME1FUo0gIXAcbM3AWqKFcR1GkUYy+/kBxKNfta9n/eehdBuwX8Yx8gJwGbM4vRbITktqVXSDKXl59IVUypFZ6PlUaKq6GWLsxsI4/O8nCPCrRm4l6mDClDzLBw+XBiLh5GqXF/i6SzqTeqi0LSRhm/s/brkGG15sUC96Xcf//1CHsKlNJtj5rA4aauOJsfvpZDwZ0lumPv6nYMr6AR/gUd1s8RltzGVWHdMIVH59SMISDpXJLX40mjVyxzKIzZWThxP2RGxADj6SkVcJCmmXPCbYRks49MeIrrJUmN+MxN75E2e1tGuHNenGQ3MVOglMdRURxz9p+3iIJGdKcZ8WbKM1MeWNcQENEnVLUgiZ0U5aEjeqttt1vAQs6eEaDHnRAoEgCDEgD9owvG1A4wf4x+RMYPDzNPRYbdfjUAt+ebfmVfx3Q3VHs3kDMRCZ7o4jC/go/m7kvl08gcYYoAe65IsASCpNUrhs9+h1JkG1BmLDi6M3zt76RsAKKdRm/jXL3nk/aGXhNWjR7+qH/R/yDkgseFdd0JIXAHsTWgrQcogqH7jpLWsytrIDxTMOv0/slz2YipzFUCVAhSb2qS0uM8Z4DBIcNAQ3dB1AnszOp93W8Bey56Pt+Q0/wTszS943/dgremfqvc/+RR+OmVZz0m3SbpWJHEeYzgSXlWAGVJmVEZ1CQw7FfPPVijtRY0PFsUfqnt3//rI4fcrk46ZHMcTGsz0QP97PVhbSkjyk9ztwi3zkfZgBR80ULC0t2JHqBQR16wDbFs4yB3u4837X1oSurJAhBU6r7JW1VQHxVUTHl+Czb0wHa+20RtqpvEQOvdwVk8dseeJYFhVABlqAAAthyU9QibXdsxyf+HHvW9M+akMHT7ZWflGUI04xNSakJMvaxC/nFiXyBc5FUSl7QewNqk5kQWLDbtOESoWdf5zYwJs4FtJ6zgH6w0V4dUVIYE7dXfuErTt5yVjOxtpOu9S19UNUfwL6GOobP73xYSNdx9jxxD1CJqgF8T49ViARKZm3smXiNtx1OOePUZIyCOeIumk5Nny5CKqRklqTO97smE0ykX63Gc0mCiV6yX063nxVdAbxgASdSQmjcnFG+GtpkQgR+7Utf+YBLTLJMo/+AnJjG/15t60jiz49xhkZzFzHJQho3SIyABTya5lRZQeP8hfRPUiiJqFO7ZzXkLZZmAOLnmY+fl0OPWOdWlFPkGcV//am1cIaZ3A98JXajGpj++B9j3STk0Z6+d4zAfj6ss5i0lcsbsVow0hiu2pm1unGo0oTiEq0r1SU5Je04/Q3eWyTT2HdT7M6eJ/GdwyPzN97pevnnZ/ZuU0iA/nM7sefq/qti/lSAUEviSxYKJ82WmE78AoTC8aK3zCciFbgaUtNSqoFJz+HCIXi+kdk5gtRnBHvaoxdPGIAwz9b1AADv9xI6eWR9GyL0bK8Lj4TgQWNVmSB2qjN2gbkqLZIjhXhCqSpKSDxPU/yhBn++kblpCzyeX3TK5XvLO4cVoRA+Nq9gLU93BsOvb0Fl4Y/y7NykvgEuI17TO2zyVIH/IqQEKEzvtJdQC2I/CkLjvbV+QK4zEI5UkMVjeM3Ll1Y3QAjntbJNlCqPmkCyeApybcUCmhYCW5XRtjOz4bA02S2vWAd8Ip9BQm9g5RCsFyeHhh3wVC4OI7qioLcA09n5dVaV2KwKTBDd0KPKpd+OlSwdxHwiOniHTb1p1F1pmUpwBVsiEsVMAAABImkC9b7yGhV5zE+BCAEB4F+37V4P8edIXJtF2W6WppF9TgS5C1IznsGCALthmtrjhcxQ7M7/DXiquV3CWG3aUJ7+naqa3c+ABTfxUQwjy2APKozuX/lWHXp5eZ8eCWUVtFvEc56m0FfKaUwRMkYE3x5WPMfjc57fpMoinN/z6lFmpmvBHmWEFi5XEB0/2N7W2r5tuNM527NGWNKIODXtZuWM925mfrBxRKp/cQCLYy86X0KFn2LhIuaGotzYBrWqIwPbF7cduauLqIx3KWzngmLN8HBIzsPn7v+Ph1qVwAACgn4YKcc0GOPQNZX5mdKvBXF3wIo2vmFZvYueXTeve0ykp+IDArg4j1jZ0EV4zzrgjVNrRK9q5KL4EMS3QYL6xM7EbfmLUyqyqBRJ/vouI7oc8wv4CGo4XjpPe/dK4sWelfVmXEe+YW1VThoTJFAQXNh3vchWZn29/G1x22JtQEPcYczPxvLWvGd0Z01QNnSItgRRL26LHGuqFDxkvHqcxYNjqeZsAd8TBasvOlSyqSjcB86glcErqmzI132/q5W3/+Ev525Hk3H1DGWefTEK4H8BZ2b+Q3KDuCphoPS0kWKoxlfySYgmBxYxbCBKjG/zQOHG08Cg4lP1ZkR773dHFbDvZZv7Zm+yjb3KooQEUVM5d9dr/vkcup3PCAs/HwwaUKUPcvD1MstFeow/ninf2a62Glu/v01RWwM1jFADwMg5SolIHqg0VmYxzYRZr+C2o/uhTjbndP9lC+OuBpu/INAs7nrZhE8upuNEwxmHvwsADdpbffHQJvkm9rw3E2E9WEavsq1vAY8w/TF/MZwoEjTZH+wpr6xmmP6pjyh2ZzyXmRJe8HRCRdGwZa0mjMpbavfdVPFMxjOdlxSz1qoHad7/oD7cbtfZksJr1HSj8Gp8WXRFXjV3AQaLodxSxAAAMnCPU5FqErdGfcywAIFNNLFtYXYvbp0cZEUyGOSeOs9BG0td9fq8E8I+i+tOPXTqFYX68BA56VatQrcNaS8kHFLhWRTRH7FKwK/fkwNwBeOAeAVw1n+VhxXZBomIoNPKAYq8xyOPJtfzjQYZUxTwp0TsQ+5pHhHfw7CznZ9cgClkZ/YaPymL96bSrnGWZTZG766z+HvGHM1RHkJke5F0uC6sEb8KildXwwF1bjjXDzBcPEcM9sYPSsHT6CT66BxChF0tHAdcecf5AwwF3b0wBhPLkU3J7FNUBWyLWFdQOQLB+teM5WsH4PjWWiMpxYHrtgsczcXEAJ0+cXFwXYq8R1I1FoT/nqHUJ2RuRlgGc4JvjIsisw3LvXflU7P2HDkE1gIfOE0+Twdcng0glb+rgu4agglE4vDGNTFeq70uCu71ukFEeA89Z6wdxFn3CYTiGSBdpYMYigOvAfXRd7c0IZpbdlixEavS0gt9itbti9sbNLHa5kOBBZEFnWsUR4vJRGz9tpF74u6VlWbZakm0oFXuAADt/EIGQG5FKlmXq46Ys34RvAHAYS0RVIh9dbYdBpSVQyGA8TUyN0MGAaCJsCXYSdsl6pNQTe6efZ7ApKfrqM6QFCqiF9WG6RitiDRWdMka11hVs5TN4lurF7mGz+qN+t5hXJEwXlCuNgd9vnbTfpYgnIcQ82RWGG45D1sOxOUFv771RiDt5xiMFER+VubB3N0S+ftuhmuxf8etxlI8dx68Z+4gRCOvMGc6dIzP1SFwHqj3KIeojIpYH/dBDPITP3Qxgua+YrK6JQ0A7/5Kj3Qwjichw1Ovu+tGUf5gdKP8xkKD1P87HrjjLNMMvq4LcsgFEBucE8r+QLgHnI+XuuOo0h49u7DuialVQYhTegsupV2r2/0cjMbOZbyXpQURyoNBh2zVPeHOZ0O/HdI6KmKEDOiuTzQLPpNoyy9mpkGG7rO2jjVNMLD2uiKgEdvfC1OWN2wD+QeINKbwUsv3n9AHCxslU0LagotutnbtWiANsvFqpf+Nk/dL43m3F+U/3DaY9eQa167jJd7pBhOGg6t8RndgndId93fAU1N0qBfZBADHkCPI5lsU9/w5XLNoXAnbQJ5I96ZVxdTLWjvcPijpXWcB6VvRah9GQL1VOjbB6hwLmDMJ6VqG0BJL+ulq0AlXpJkbWd0b/OeMVWj/Q0ZV4/ea6kII87Z+E1d1InTHMOymNOutDERM6TzViyg5pbvCL8Kj/IORzOJgOMSle5txbu2sjc1JTtjzv88i35TtX25txflG+fYYpECvC1GhxibmAWXXbAgaPqf0Phum78i82h5Z4EKXTIYakVkaRmc6yN+ZcfL9CBof7XPaZJhXlRvclD2cXQeNNDwr5DGV3F1vSh2GAoIIFPs++x8aD8USXhwDu+0O//Q2vnmPv2w0vCM31YQMA1ephZizSILv5qFH2dsNqdB9F47xjV1M3nFEx6WMoceggAvcQBvuU/9Gn3Iwuw+LAhyJsO4BQ8N6DEcofil/JjPR/7Pkg+we/dyF58bu6IHbaHdX++RT3nfmeIFMgDXngWZgxjPRNmj9ViobfriiWFKtwe5zT+fY2H/xXkTplBMCApEfeDcMSC3IHdx8aE6owye87OTAnD/qEb9XzO6FAsEAsjAY9ziTWraK586NuvR7lOYApyTt6wLo033Xl9/53jb2FWMxW8Gctg5+n9ESXuZ13hHB1yr80bneg5/1I2Je3rNM8gH/eJCZJum35UMTvf7Zb+wMJ/KStbyYkgD10H+XPcm/sdjbfJlGXd14NioxlYc4eKfiDmL24EdPopbUMz7WviY+dziiahCwnYgkYvPsAN/MqAJEaUm95DeKGMG6/8gS4AV3tUVdbuC2rPRBFUMykbbanRBVBu7gWbClK1cglCX1CTi5sZD099+IIbTzRZ9uN0RyEwjBkKdzfSx731KwLK8Xgl0AjL7kEVbyu/TzbH5ImpaxvaIFCTyHKrmqnT+cA6+ZHhXPlwmfCAPLFEYeJQ/iizUIjUA6d/mAXGoLXqqAB3w+QGSPOKCSeDSeg5iRFEM7bvHKiq4RZlQVubqHhMRkO3w7X3KAZFR0FNwUwNeUnhvfp7s0Yc1TA7J7vryavdNpt/ulVY1BwWERC+K5HXRZ8LF5VD9tnP0ddp9uO/S3/Lsyuv2tv52QAzu+nnuYBlTbttXEAhhUdP26A2XO7+8RptZa7n286H5sPbt60emCA33aKs8O5Njpo5fL/g81Gh3rz4p+2Vh6bcFydl18ho08fpjvaHpNXMWJ4gquob9xJerNj55/fLXl+uY+H6GbULCuJeMaY9qsRz4HZnvPcFaBMBMBe/hrsd8J5cbjqr1VKlgA3MY59j96j69u0J+eDm8x5LzzGR/vdMpIfFBqpRG207pajPuZXKb/SOW/Ejx/8DJjw+LDeMaYoZ1/xjTHvJjrrgPXLW8wxtanEuVvhf5UrpmBG3Z8SuJqJDYPoAxBOHmxXVZzLJdBqle6DIFxrHF1xMgDdjA2MaOvX+LDF5PDj/OyAGi8bD27Eik84HHD3gpivTkbfwMmPMLnP3icUDyUO2lwQw1TpvwukZ7P/ORtgisf/WwW4+La1tTwH5N8QJhBg/iv/lE4DZGGEGXcAAAAAAAAAsWnAAAA==";

// ui/images/airfrog-pro-top.webp
var airfrog_pro_top_default = "data:image/webp;base64,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";

// ui/images/renders.js
var RENDERS = { "mini": airfrog_mini_top_default, "pro": airfrog_pro_top_default };

// ui/images/boards.json
var boards_default = {
  mini: {
    width: 306,
    height: 533,
    J1: [
      45,
      5,
      216,
      87
    ],
    J2: [
      0,
      48,
      42,
      389
    ]
  },
  pro: {
    width: 313,
    height: 599,
    J1: [
      48,
      5,
      216,
      87
    ],
    J2: [
      0,
      48,
      42,
      389
    ]
  }
};

// ui/src/ui/pins.js
var CONNECTORS = {
  J1: { pins: ["GND", "5V", null, null, null, null, "GND", null, "GND", null] },
  J2: { pins: ["GND", null, null, "DTR", "RTS", "BOOT", "RXD0", "TXD0", "EN"], same: { 2: "J1-3", 3: "J1-5" } }
};
var BOX = { line: 3, top: 34, left: 52, gap: 8 };
var BOARD_PX = 240;
function connectorPins(entries) {
  const out = [];
  for (const [connector, { pins, same = {} }] of Object.entries(CONNECTORS)) {
    pins.forEach((own, i) => {
      const pin = `${connector}-${i + 1}`;
      const line = same[i + 1] ?? pin;
      out.push({ pin, name: own ?? entries.filter((e) => e.pin === line).map((e) => e.name).join(" / ") });
    });
  }
  return out;
}
var SVG = "http://www.w3.org/2000/svg";
function svg(tag, attrs = {}, text = null) {
  const e = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) {
    e.setAttribute(k, v);
  }
  if (text !== null) {
    e.textContent = text;
  }
  return e;
}
var PITCH = 26;
var LABEL = 135;
var LABEL_MARGIN = 2;
var measure;
function labelWidth(p) {
  measure ??= document.createElement("canvas").getContext?.("2d") ?? null;
  if (!measure) {
    return LABEL;
  }
  measure.font = CONNECTOR_NUM_FONT;
  const num = measure.measureText(`${p.pin} `).width;
  measure.font = `600 ${CONNECTOR_FONT}`;
  return Math.ceil(num + measure.measureText(p.name).width) + LABEL_MARGIN;
}
function drawing(connector, pins) {
  const two = connector === "J1";
  const rows2 = two ? pins.length / 2 : pins.length;
  const cols = two ? 2 : 1;
  const onLeft = (i) => two && i % 2 === 0;
  const widest = (left2) => Math.max(0, ...pins.filter((_, i) => onLeft(i) === left2).map(labelWidth));
  const left = two ? widest(true) + 6 : 0;
  const innerWidth = left + cols * PITCH + 18 + widest(false);
  const innerHeight = rows2 * PITCH + 14;
  const [width, height] = two ? [innerHeight, innerWidth] : [innerWidth, innerHeight];
  const root = svg("svg", {
    viewBox: `0 0 ${width} ${height}`,
    width,
    role: "img",
    "aria-label": PINS.CONNECTOR(connector),
    class: "connector"
  });
  const bx = left + 6;
  const header = svg("g", two ? { transform: `translate(0 ${height}) rotate(-90)` } : {});
  header.append(svg("rect", {
    x: bx - 6,
    y: 0,
    width: cols * PITCH + 12,
    height: rows2 * PITCH + 8,
    rx: 4,
    class: "body"
  }));
  pins.forEach((p, i) => {
    const col = two ? i % 2 : 0;
    const row = two ? Math.floor(i / 2) : i;
    const cx = bx + col * PITCH + PITCH / 2;
    const cy = 4 + row * PITCH + PITCH / 2;
    header.append(i === 0 ? svg("rect", { x: cx - 7, y: cy - 7, width: 14, height: 14, class: "pin" }) : svg("circle", { cx, cy, r: 7, class: "pin" }));
    const x = onLeft(i) ? bx - 12 : bx + cols * PITCH + 12;
    const label = svg("text", { x, y: cy + 4, "text-anchor": onLeft(i) ? "end" : "start" });
    const parts = onLeft(i) ? [[p.name, "name"], [`${p.pin} `, "num"]].reverse() : [[`${p.pin} `, "num"], [p.name, "name"]];
    for (const [t, cls] of parts) {
      label.append(svg("tspan", { class: cls }, t));
    }
    header.append(label);
  });
  root.append(header);
  return root;
}
function render(model) {
  const key = MODELS[model]?.key;
  const b = boards_default[key];
  if (!RENDERS[key] || !b) {
    return null;
  }
  const { line, top, left, gap } = BOX;
  const width = b.width + 2 * left;
  const root = svg("svg", {
    viewBox: `${-left} ${-top} ${width} ${b.height + top}`,
    role: "img",
    width: Math.round(BOARD_PX * width / b.width),
    "aria-label": PINS.BOARD(modelName(model)),
    class: "board"
  });
  root.append(svg("image", { href: RENDERS[key], width: b.width, height: b.height }));
  for (const connector of Object.keys(CONNECTORS)) {
    const [x, y, w, h2] = b[connector];
    const above = connector === "J1";
    root.append(
      svg("rect", {
        x: x + line / 2,
        y: y + line / 2,
        width: w - line,
        height: h2 - line,
        rx: 4,
        "stroke-width": line,
        class: "box"
      }),
      svg(
        "text",
        above ? { x: x + w / 2, y: -gap, "text-anchor": "middle", class: "label" } : { x: -gap, y: y + h2 / 2, "text-anchor": "end", "dominant-baseline": "central", class: "label" },
        connector
      )
    );
  }
  return root;
}
var PinsView = class {
  constructor() {
    this.board = h("div", { class: "board-render" });
    this.connectors = h("div", { class: "connectors" });
    this.element = card(PINS.TITLE, PINS.TIP, this.board, this.connectors);
    this.key = null;
    this.model = null;
  }
  update({ pinMap, target, hw }) {
    const model = hw?.model ?? null;
    if (model !== this.model) {
      this.model = model;
      this.board.replaceChildren(...[render(model)].filter((e) => e));
    }
    const entries = target?.identified() ? pinMap?.entries ?? [] : [];
    const key = JSON.stringify(entries);
    if (key === this.key) {
      return;
    }
    this.key = key;
    const pins = connectorPins(entries);
    this.connectors.replaceChildren(...Object.keys(CONNECTORS).map((c) => {
      const own = pins.filter((p) => p.pin.startsWith(`${c}-`));
      return h(
        "div",
        { class: "connector-row" },
        drawing(c, own),
        h(
          "table",
          {},
          h("thead", {}, h("tr", {}, h("th", {}, PINS.PIN), h("th", {}, PINS.NAME))),
          h("tbody", {}, ...own.map((p) => h(
            "tr",
            {},
            h("td", { class: "mono" }, p.pin),
            h("td", {}, p.name || VALUES.NONE)
          )))
        )
      );
    }));
  }
};

// js/setup/download.js
var DownloadError = class extends Error {
  /**
   * @param {string} message - for developers
   * @param {object} [why] - neither for a server that can't be reached
   * @param {number|null} [why.status] - an HTTP error's status
   * @param {boolean} [why.timedOut] - nothing was received in time
   */
  constructor(message2, { status = null, timedOut = false } = {}) {
    super(message2);
    this.status = status;
    this.timedOut = timedOut;
  }
};
async function download(url, { fetch: fetchFn = fetch, timeoutMs = DOWNLOAD_TIMEOUT_MS, ...options } = {}) {
  const abort = new AbortController();
  let timedOut = false;
  let timer = null;
  const received = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      timedOut = true;
      abort.abort();
    }, timeoutMs);
  };
  try {
    received();
    const response = await fetchFn(url, { ...options, signal: abort.signal });
    if (!response.ok) {
      throw new DownloadError(`HTTP ${response.status}: ${url}`, { status: response.status });
    }
    const reader = response.body.getReader();
    const chunks = [];
    for (; ; ) {
      received();
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      chunks.push(value);
    }
    return new Uint8Array(await new Blob(chunks).arrayBuffer());
  } catch (e) {
    throw e instanceof DownloadError ? e : new DownloadError(e.message, { timedOut });
  } finally {
    clearTimeout(timer);
  }
}

// ui/src/extensions/semver.js
var SEMVER = new RegExp("^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$");
function parse(version) {
  const m = typeof version === "string" ? SEMVER.exec(version) : null;
  if (!m) {
    return null;
  }
  return { core: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ? m[4].split(".") : [] };
}
function isVersion(version) {
  return parse(version) !== null;
}
function compareIdentifier(a, b) {
  const na = /^\d+$/.test(a);
  const nb = /^\d+$/.test(b);
  if (na && nb) {
    return Math.sign(Number(a) - Number(b));
  }
  if (na !== nb) {
    return na ? -1 : 1;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}
function compare(a, b) {
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) {
    throw new TypeError(`Not a semantic version: ${pa ? b : a}`);
  }
  for (let i = 0; i < 3; i++) {
    if (pa.core[i] !== pb.core[i]) {
      return Math.sign(pa.core[i] - pb.core[i]);
    }
  }
  if (!pa.pre.length || !pb.pre.length) {
    return (pa.pre.length ? -1 : 0) + (pb.pre.length ? 1 : 0);
  }
  for (let i = 0; i < Math.min(pa.pre.length, pb.pre.length); i++) {
    const c = compareIdentifier(pa.pre[i], pb.pre[i]);
    if (c) {
      return c;
    }
  }
  return Math.sign(pa.pre.length - pb.pre.length);
}

// ui/src/extensions/list.js
var NAME = new RegExp(`^[a-z0-9](?:[a-z0-9-]{0,${EXT_NAME_MAX - 2}}[a-z0-9])?$`);
var SHA256 = /^[0-9a-f]{64}$/;
var WAMR = /^\d+\.\d+\.\d+$/;
var NO_MODULE = { model: 0, wamr: "0.0.0" };
var ExtensionError = class extends Error {
};
function isName(name) {
  return typeof name === "string" && NAME.test(name);
}
var isText = (v) => typeof v === "string" && v !== "";
function isLocal(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost");
  } catch (e) {
    return false;
  }
}
function uiAddress(ui, local) {
  if (typeof ui !== "string") {
    return null;
  }
  try {
    const u = new URL(ui);
    return u.protocol === "https:" || local && isLocal(ui) ? u.href : null;
  } catch (e) {
    return null;
  }
}
function checkMetadata(m) {
  const ok = m && typeof m === "object" && isName(m.name) && isText(m.display_name) && isVersion(m.version) && typeof m.description === "string" && typeof m.author === "string" && (m.source === void 0 || typeof m.source === "string") && Array.isArray(m.firmware) && m.firmware.every(isText) && (m.ui === void 0 || typeof m.ui === "string");
  return ok ? m : null;
}
function parseMetadata(bytes) {
  if (bytes.length > EXT_METADATA_MAX) {
    return null;
  }
  try {
    return checkMetadata(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
  } catch (e) {
    return null;
  }
}
function checkImage(i) {
  return i && Number.isInteger(i.model) && i.model >= 0 && i.model <= 65535 && typeof i.wamr === "string" && WAMR.test(i.wamr) && typeof i.url === "string" && /^https?:\/\//.test(i.url) && Number.isInteger(i.size) && i.size > 0 && typeof i.sha256 === "string" && SHA256.test(i.sha256);
}
function checkList(manifest) {
  const out = /* @__PURE__ */ new Map();
  const extensions = manifest?.extensions;
  if (!extensions || typeof extensions !== "object" || Array.isArray(extensions)) {
    return out;
  }
  for (const [name, entry] of Object.entries(extensions)) {
    if (!isName(name) || typeof entry?.depublished !== "boolean" || !Array.isArray(entry.versions)) {
      console.warn(`Extension list: ${name} left out`);
      continue;
    }
    const versions = entry.versions.filter((v) => checkMetadata(v?.metadata)?.name === name && Array.isArray(v.images) && v.images.length > 0 && v.images.every(checkImage));
    if (versions.length !== entry.versions.length) {
      console.warn(`Extension list: ${entry.versions.length - versions.length} versions of ${name} left out`);
    }
    if (versions.length) {
      versions.sort((a, b) => compare(b.metadata.version, a.metadata.version));
      out.set(name, { name, depublished: entry.depublished, versions });
    }
  }
  return out;
}
function pickImage(images, model, wamr) {
  return images.find((i) => i.model === model && i.wamr === wamr) ?? images.find((i) => i.model === NO_MODULE.model && i.wamr === NO_MODULE.wamr) ?? null;
}
function latest(entry, model, wamr) {
  for (const v of entry?.versions ?? []) {
    const image = pickImage(v.images, model, wamr);
    if (image) {
      return { metadata: v.metadata, image };
    }
  }
  return null;
}
function findVersion(entry, version, model, wamr) {
  const v = entry?.versions.find((x) => x.metadata.version === version);
  const image = v && pickImage(v.images, model, wamr);
  return image ? { metadata: v.metadata, image } : null;
}
function wamrText(bytes) {
  return Array.from(bytes).join(".");
}
function checkHeader(bytes, expected) {
  const header = decodeExtImage(bytes);
  if (!header || header.magic !== EXT_IMAGE_MAGIC || header.name !== expected.name || header.model !== expected.model || wamrText(header.wamr) !== expected.wamr || header.metadataOffset + header.metadataLen > bytes.length || header.moduleOffset + header.moduleLen > bytes.length) {
    throw new ExtensionError(ERRORS.EXTENSION_INVALID());
  }
  return header;
}
function imageMetadata(bytes, header) {
  return parseMetadata(bytes.subarray(header.metadataOffset, header.metadataOffset + header.metadataLen));
}
function checkDownload(bytes, name, image) {
  if (bytes.length !== image.size || hex2(sha256(bytes)) !== image.sha256) {
    throw new ExtensionError(EXTENSIONS.CORRUPT);
  }
  checkHeader(bytes, { name, model: image.model, wamr: image.wamr });
}
function targetGroup(firmware, found) {
  if (!firmware.length) {
    return "any";
  }
  return firmware.some((f) => Firmware[f] !== void 0 && Firmware[f] === found) ? "this" : "other";
}
function firmwareText(name) {
  return FIRMWARE[Firmware[name]]?.name ?? name;
}

// ui/src/download.js
function downloadText(e) {
  if (e.timedOut) {
    return HOME_PAGE.DOWNLOAD_TIMED_OUT;
  }
  return e.status === null ? HOME_PAGE.DOWNLOAD_FAILED : HOME_PAGE.DOWNLOAD_HTTP(e.status);
}

// ui/src/extensions/zip.js
var EOCD = 101010256;
var CENTRAL = 33639248;
var LOCAL = 67324752;
var STORED = 0;
var DEFLATED = 8;
var ZipError = class extends Error {
};
var crcTable = null;
function crc32(bytes) {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) {
        c = c & 1 ? 3988292384 ^ c >>> 1 : c >>> 1;
      }
      crcTable[n] = c >>> 0;
    }
  }
  let crc = 4294967295;
  for (const b of bytes) {
    crc = crcTable[(crc ^ b) & 255] ^ crc >>> 8;
  }
  return (crc ^ 4294967295) >>> 0;
}
async function inflate(data, size) {
  const reader = new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  const out = new Uint8Array(size);
  let at = 0;
  for (; ; ) {
    const { done, value: chunk } = await reader.read();
    if (done) {
      break;
    }
    if (at + chunk.length > size) {
      throw new ZipError("entry larger than its recorded size");
    }
    out.set(chunk, at);
    at += chunk.length;
  }
  if (at !== size) {
    throw new ZipError("entry smaller than its recorded size");
  }
  return out;
}
async function readZip(zip, { maxSize, maxTotal }, want = () => true) {
  const v = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  let end = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 22 - 65535); i--) {
    if (v.getUint32(i, true) === EOCD) {
      end = i;
      break;
    }
  }
  if (end < 0) {
    throw new ZipError("no end of central directory");
  }
  const count = v.getUint16(end + 10, true);
  let at = v.getUint32(end + 16, true);
  const entries = [];
  const names = new TextDecoder();
  for (let n = 0; n < count; n++) {
    if (at + 46 > zip.length || v.getUint32(at, true) !== CENTRAL) {
      throw new ZipError("bad central directory");
    }
    const flags = v.getUint16(at + 8, true);
    const method = v.getUint16(at + 10, true);
    const crc = v.getUint32(at + 16, true);
    const packed = v.getUint32(at + 20, true);
    const size = v.getUint32(at + 24, true);
    const nameLen = v.getUint16(at + 28, true);
    const local = v.getUint32(at + 42, true);
    const name = names.decode(zip.subarray(at + 46, at + 46 + nameLen));
    at += 46 + nameLen + v.getUint16(at + 30, true) + v.getUint16(at + 32, true);
    if (local + 30 > zip.length || v.getUint32(local, true) !== LOCAL) {
      throw new ZipError(`bad local header for ${name}`);
    }
    const start2 = local + 30 + v.getUint16(local + 26, true) + v.getUint16(local + 28, true);
    entries.push({ name, flags, method, crc, packed, size, local, start: start2, end: start2 + packed });
  }
  const spans = [...entries].sort((a, b) => a.local - b.local);
  for (let i = 1; i < spans.length; i++) {
    if (spans[i].local < spans[i - 1].end) {
      throw new ZipError(`${spans[i - 1].name} and ${spans[i].name} overlap`);
    }
  }
  const wanted = entries.filter((e) => !e.name.endsWith("/") && want(e.name));
  if (wanted.reduce((total, e) => total + e.size, 0) > maxTotal) {
    throw new ZipError("files too large together");
  }
  const files = /* @__PURE__ */ new Map();
  for (const { name, flags, method, crc, packed, size, start: start2 } of wanted) {
    if (flags & 1) {
      throw new ZipError(`${name} is encrypted`);
    }
    if (size > maxSize || packed === 4294967295) {
      throw new ZipError(`${name} too large`);
    }
    if (start2 + packed > zip.length) {
      throw new ZipError(`${name} truncated`);
    }
    const data = zip.subarray(start2, start2 + packed);
    let bytes;
    if (method === STORED) {
      if (packed !== size) {
        throw new ZipError(`${name}'s sizes differ`);
      }
      bytes = data.slice();
    } else if (method === DEFLATED) {
      try {
        bytes = await inflate(data, size);
      } catch (e) {
        throw e instanceof ZipError ? e : new ZipError(`${name}: ${e.message}`);
      }
    } else {
      throw new ZipError(`${name} uses compression method ${method}`);
    }
    if (crc32(bytes) !== crc) {
      throw new ZipError(`${name}'s CRC-32 is wrong`);
    }
    files.set(name, bytes);
  }
  return files;
}

// ui/src/extensions/package.js
var MAX_ENTRY = 1024 * 1024;
var MAX_TOTAL = 4 * 1024 * 1024;
async function readPackage(bytes, model, wamr) {
  let files;
  try {
    files = await readZip(
      bytes,
      { maxSize: MAX_ENTRY, maxTotal: MAX_TOTAL },
      (path) => path === "extension-meta.json" || /^images\/[^/]+$/.test(path)
    );
  } catch (e) {
    console.warn(`Extension package: ${e.message}`);
    throw new ExtensionError(EXTENSIONS.INVALID_FILE);
  }
  const meta = files.get("extension-meta.json");
  const metadata = meta && parseMetadata(meta);
  if (!metadata) {
    throw new ExtensionError(EXTENSIONS.INVALID_FILE);
  }
  const images = [];
  for (const [path, data] of files) {
    const header2 = path.startsWith("images/") ? decodeExtImage(data) : null;
    if (header2?.magic === EXT_IMAGE_MAGIC && header2.name === metadata.name) {
      images.push({ model: header2.model, wamr: wamrText(header2.wamr), data });
    }
  }
  if (!images.length) {
    throw new ExtensionError(EXTENSIONS.INVALID_FILE);
  }
  const chosen = pickImage(images, model, wamr);
  if (!chosen) {
    throw new ExtensionError(ERRORS.EXTENSION_UNSUPPORTED());
  }
  let header;
  try {
    header = checkHeader(chosen.data, { name: metadata.name, model: chosen.model, wamr: chosen.wamr });
  } catch (e) {
    throw new ExtensionError(EXTENSIONS.INVALID_FILE);
  }
  const stored = imageMetadata(chosen.data, header);
  if (stored?.name !== metadata.name) {
    throw new ExtensionError(EXTENSIONS.INVALID_FILE);
  }
  return { metadata: stored, image: chosen.data };
}

// ui/src/extensions/tab.js
var DEFAULT_TABS = 3;
var CMD_MS = 5e3;
function moved(list, from, to) {
  const out = [...list];
  const [item] = out.splice(from, 1);
  out.splice(to, 0, item);
  return out;
}
function stateText(wasmState) {
  if (wasmState === WasmState.NO_MODULE) {
    return EXTENSIONS.UI_ONLY;
  }
  return wasmState === WasmState.RUNNING ? EXTENSIONS.RUNNING : EXTENSIONS.STOPPED;
}
var ExtensionsTab = class {
  /** @type {Array<Installed>} */
  installed = [];
  /** @type {Map<string, object>|null} the checked extensions manifest */
  list = null;
  listError = null;
  busy = false;
  #listLoad = null;
  #dragFrom = null;
  /**
   * @param {object} options
   * @param {function(): object|null} options.airfrog - the open connection
   * @param {function(): object} options.state - Airfrog's state the Page read
   * @param {function(): Promise<{url: string, manifest: object}>} options.loadExtensions -
   *        loads and verifies the extensions manifest
   * @param {string|null} options.extensionsUrl - the extensions manifest's
   *        address, or null when it isn't known
   * @param {function(Array<Installed>)} options.onChange - called after the
   *        installed extensions change
   * @param {function(string)} options.onUpdated - called after an extension
   *        is installed again
   * @param {function(string)} options.open - displays an extension UI
   */
  constructor({ airfrog, state, loadExtensions, extensionsUrl, onChange, onUpdated, open }) {
    this.airfrog = airfrog;
    this.state = state;
    this.loadExtensions = loadExtensions;
    this.extensionsUrl = extensionsUrl;
    this.onChange = onChange;
    this.onUpdated = onUpdated;
    this.openUi = open;
    this.rows = h("tbody");
    this.none = h("p", { class: "note", hidden: true }, EXTENSIONS.NONE_INSTALLED);
    this.msg = message();
    this.confirm = prompt();
    this.file = h("input", { type: "file", accept: ".afx", hidden: true, onchange: () => this.#chosen() });
    this.addButton = button(EXTENSIONS.ADD, () => this.#showAdd(true));
    this.fileButton = button(EXTENSIONS.FROM_FILE, () => this.file.click());
    this.table = h(
      "table",
      { class: "exts" },
      h("thead", {}, h(
        "tr",
        {},
        h("th"),
        h("th", {}, EXTENSIONS.EXTENSION),
        h("th", {}, EXTENSIONS.VERSION),
        h("th", {}, EXTENSIONS.STATE),
        h("th", {}, EXTENSIONS.TAB_COLUMN),
        h("th")
      )),
      this.rows
    );
    this.installedView = h(
      "section",
      { class: "card" },
      h("div", { class: "card-head" }, h("h2", {}, EXTENSIONS.INSTALLED_TITLE)),
      this.table,
      this.none,
      h("p", { class: "note drag-note" }, EXTENSIONS.DRAG_NOTE),
      h("div", { class: "row actions" }, this.addButton, this.fileButton, this.file),
      this.msg,
      this.confirm.element
    );
    this.search = h("input", { type: "search", name: "search", autocomplete: "off", oninput: () => this.render() });
    this.fAny = check("any", EXTENSIONS.ANY_TARGET, null, { checked: true, onchange: () => this.render() });
    this.fThis = check("this", "", null, { checked: true, onchange: () => this.render() });
    this.fOther = check("other", EXTENSIONS.OTHER_TARGETS, null, { onchange: () => this.render() });
    this.count = h("div", { class: "count" });
    this.addMsg = message();
    this.addConfirm = prompt();
    this.avail = h("ul", { class: "avail" });
    this.addView = h(
      "section",
      { class: "card", hidden: true },
      h(
        "div",
        { class: "card-head" },
        h("h2", {}, EXTENSIONS.ADD),
        button(EXTENSIONS.BACK, () => this.#showAdd(false), { class: "cancel right" })
      ),
      h("label", {}, h("span", {}, EXTENSIONS.SEARCH), this.search),
      h(
        "div",
        { class: "filters" },
        h("span", { class: "muted" }, EXTENSIONS.FOR),
        this.fAny.element,
        this.fThis.element,
        this.fOther.element
      ),
      this.count,
      h("div", { class: "add-status" }, this.addMsg),
      this.avail,
      this.addConfirm.element
    );
    this.element = h("div", {}, this.installedView, this.addView);
  }
  get connected() {
    return Boolean(this.airfrog()) && Boolean(this.state().connected);
  }
  /** The model and WAMR version from the state the Page read, or null. */
  #info() {
    const { hw, fw } = this.state();
    return hw && fw ? { model: hw.model, wamr: fw.wamr } : null;
  }
  /** Reads GET_HW_INFO and GET_FW_INFO for an install. */
  async #readInfo(airfrog) {
    const hw = parseHwInfo(await airfrog.airfrogCmd(Command.GET_HW_INFO, EMPTY2, CMD_MS));
    const fw = parseFwInfo(await airfrog.airfrogCmd(Command.GET_FW_INFO, EMPTY2, CMD_MS));
    return { model: hw.model, wamr: fw.wamr };
  }
  /** Called when the tab is displayed. */
  shown() {
    this.loadList();
    this.refresh();
  }
  /**
   * Loads the extensions manifest. A call while one loads waits for that
   * load. A failure is displayed and the extensions manifest loaded before
   * is kept.
   */
  loadList() {
    this.#listLoad ??= (async () => {
      try {
        const { url, manifest } = await this.loadExtensions();
        this.list = checkList(manifest);
        this.extensionsUrl = url;
        if (this.listError) {
          this.addMsg.say("");
        }
        this.listError = null;
      } catch (e) {
        this.listError = `${EXTENSIONS.LIST_NOT_LOADED} ${errorText(e)}`;
        this.addMsg.say(this.listError, "bad");
      } finally {
        this.#listLoad = null;
      }
      this.#changed();
    })();
    return this.#listLoad;
  }
  /** Reads the installed extensions and their metadata from Airfrog. */
  async refresh() {
    const airfrog = this.airfrog();
    if (!airfrog) {
      return;
    }
    try {
      const entries = await airfrog.getExtensions();
      const items = [];
      for (const e of entries) {
        const name = e.name;
        let metadata = null;
        try {
          metadata = checkMetadata(await airfrog.getExtensionMetadata(name));
        } catch (err) {
          if (airfrog.isClosed()) {
            throw err;
          }
        }
        const sideLoaded = Boolean(e.flags & ExtensionFlag.SIDE_LOADED);
        items.push({
          name,
          flags: e.flags,
          wasmState: e.wasmState,
          wasmReason: e.wasmReason,
          metadata,
          displayName: metadata?.display_name ?? name,
          version: metadata?.version ?? null,
          ui: null,
          sideLoaded,
          tab: Boolean(e.flags & ExtensionFlag.TAB)
        });
      }
      this.installed = items;
    } catch (e) {
      if (!airfrog.isClosed()) {
        (this.addView.hidden ? this.msg : this.addMsg).say(`${EXTENSIONS.READ_FAILED} ${errorText(e)}`, "bad");
      }
      return;
    }
    this.#changed();
  }
  /**
   * Passes on the installed extensions, each with its UI address checked
   * against the extensions manifest's address as it is now (D1a).
   */
  #changed() {
    const local = isLocal(this.extensionsUrl);
    this.installed = this.installed.map((x) => ({ ...x, ui: uiAddress(x.metadata?.ui, x.sideLoaded || local) }));
    this.onChange(this.installed);
    this.render();
  }
  render() {
    const disabled = !this.connected || this.busy;
    this.addButton.disabled = disabled;
    this.fileButton.disabled = disabled;
    this.none.hidden = this.installed.length > 0;
    this.table.hidden = this.installed.length === 0;
    this.rows.replaceChildren(...this.installed.map((x, i) => this.#row(x, i, disabled)));
    this.#renderAvail(disabled);
  }
  /** The installed version's note: latest version, side-loaded or Depublished. */
  #note(x) {
    if (x.sideLoaded) {
      return EXTENSIONS.SIDE_LOADED;
    }
    const entry = this.list?.get(x.name);
    if (!entry) {
      return null;
    }
    if (entry.depublished) {
      return EXTENSIONS.DEPUBLISHED;
    }
    const info = this.#info();
    const newest = info ? latest(entry, info.model, info.wamr) : null;
    return EXTENSIONS.LATEST(VALUES.VERSION((newest?.metadata ?? entry.versions[0].metadata).version));
  }
  /** The newer version Update installs, or null. */
  #newer(x) {
    const entry = this.list?.get(x.name);
    const info = this.#info();
    if (x.sideLoaded || !entry || entry.depublished || !info || !x.version) {
      return null;
    }
    const newest = latest(entry, info.model, info.wamr);
    return newest && compare(newest.metadata.version, x.version) > 0 ? newest.metadata.version : null;
  }
  /** An installed extension's buttons in the installed list and in Install extensions. */
  #actions(x, disabled, msg, confirm) {
    const newer = this.#newer(x);
    const reinstall = !x.sideLoaded && x.wasmReason === WasmReason.OTHER_WAMR_VERSION && (x.wasmState === WasmState.STOPPED || x.wasmState === WasmState.NOT_STARTED);
    return [
      x.ui ? button(EXTENSIONS.OPEN, () => this.openUi(x.name), { class: "small", disabled: !this.connected }) : null,
      newer ? this.#button(
        EXTENSIONS.UPDATE,
        () => this.#fromRepository(x.name, null, msg),
        { class: "small", disabled }
      ) : null,
      reinstall ? this.#button(
        EXTENSIONS.REINSTALL,
        () => this.#fromRepository(x.name, x.version, msg),
        { class: "small", disabled }
      ) : null,
      this.#button(EXTENSIONS.REMOVE, () => {
        msg.say("");
        confirm.ask(
          EXTENSIONS.REMOVE_CONFIRM(x.displayName),
          EXTENSIONS.REMOVE,
          () => this.#remove(x, msg),
          { danger: true }
        );
      }, { class: "small danger", disabled })
    ];
  }
  /** A button that acts on a single click and not while an operation runs. */
  #button(text, onclick, attrs) {
    return button(text, (e) => {
      if (e.detail <= 1 && !this.busy) {
        onclick();
      }
    }, attrs);
  }
  #row(x, i, disabled) {
    const note = this.#note(x);
    const tab = x.ui ? h("input", {
      type: "checkbox",
      checked: x.tab,
      disabled,
      "aria-label": EXTENSIONS.TAB_CHECKBOX(x.displayName),
      onchange: (e) => this.#save(this.installed.map((y) => y === x ? { ...y, tab: e.target.checked } : y))
    }) : null;
    const tr = h(
      "tr",
      { draggable: !disabled, class: "ext-row", "data-name": x.name },
      h("td", { class: "handle", "aria-hidden": "true" }, "\u283F"),
      h("td", {}, x.displayName),
      h(
        "td",
        { class: "ver" },
        x.version ? VALUES.VERSION(x.version) : VALUES.NONE,
        note ? [" ", h("span", { class: "muted" }, note)] : null
      ),
      h("td", {}, stateText(x.wasmState)),
      h("td", {}, tab),
      h("td", { class: "acts" }, ...this.#actions(x, disabled, this.msg, this.confirm))
    );
    tr.addEventListener("dragstart", (e) => {
      this.#dragFrom = i;
      e.dataTransfer?.setData("text/plain", x.name);
      tr.classList.add("dragging");
    });
    tr.addEventListener("dragend", () => tr.classList.remove("dragging"));
    tr.addEventListener("dragover", (e) => e.preventDefault());
    tr.addEventListener("drop", (e) => {
      e.preventDefault();
      const from = this.#dragFrom;
      this.#dragFrom = null;
      if (from !== null && from !== i && !this.busy) {
        this.#save(moved(this.installed, from, i));
      }
    });
    return tr;
  }
  #renderAvail(disabled) {
    const target = this.state().target;
    const found = target?.identified() && FIRMWARE[target.firmware] ? target.firmware : 0;
    this.fThis.element.hidden = !found;
    this.fThis.element.lastChild.textContent = found ? FIRMWARE[found].name : "";
    const info = this.#info();
    const installed = new Map(this.installed.map((x) => [x.name, x]));
    const all = [...this.list?.values() ?? []].filter((e) => !e.depublished).map((e) => {
      const newest = (info && latest(e, info.model, info.wamr)) ?? { metadata: e.versions[0].metadata };
      return { name: e.name, metadata: newest.metadata };
    });
    const q = this.search.value.trim().toLowerCase();
    const groups = { any: this.fAny.box.checked, this: found && this.fThis.box.checked, other: this.fOther.box.checked };
    const shown = all.filter(({ name, metadata: m }) => groups[targetGroup(m.firmware, found)] && (!q || [name, m.display_name, m.description, m.author].join(" ").toLowerCase().includes(q))).sort((a, b) => a.metadata.display_name.localeCompare(b.metadata.display_name));
    this.count.textContent = this.list ? EXTENSIONS.COUNT(shown.length, all.length) : "";
    this.avail.replaceChildren(...shown.map(({ name, metadata: m }) => h(
      "li",
      {},
      h(
        "div",
        { class: "body" },
        h(
          "div",
          { class: "top" },
          nameLink(m),
          h("span", { class: "ver muted" }, VALUES.VERSION(m.version)),
          ...(m.firmware.length ? m.firmware : [null]).map((f) => h(
            "span",
            { class: f !== null && targetGroup([f], found) === "this" ? "for this" : "for" },
            f === null ? EXTENSIONS.ANY_TARGET : firmwareText(f)
          ))
        ),
        h("div", { class: "desc" }, m.description, " \xB7 ", h("span", { class: "muted" }, m.author))
      ),
      h("div", { class: "acts" }, ...installed.get(name) ? this.#actions(installed.get(name), disabled, this.addMsg, this.addConfirm) : [this.#button(
        EXTENSIONS.INSTALL,
        () => this.#fromRepository(name, null, this.addMsg),
        { class: "small", disabled }
      )])
    )));
  }
  #showAdd(on) {
    this.installedView.hidden = on;
    this.addView.hidden = !on;
    this.addMsg.say("");
    this.addConfirm.element.hidden = true;
    this.confirm.element.hidden = true;
    if (on) {
      this.loadList();
      this.search.focus?.();
    }
    this.render();
  }
  /** Runs fn as the tab's one operation, with buttons disabled. */
  async #run(fn) {
    if (this.busy) {
      return;
    }
    this.busy = true;
    this.confirm.element.hidden = true;
    this.addConfirm.element.hidden = true;
    this.render();
    try {
      await fn();
    } finally {
      this.busy = false;
      this.render();
    }
  }
  /** Saves the order and Tab checkboxes of list with SET_EXTENSIONS. */
  #save(list) {
    this.#run(async () => {
      const airfrog = this.airfrog();
      this.installed = list;
      this.#changed();
      this.msg.say(SETTINGS.SAVING);
      try {
        await airfrog.setExtensions(list.map((x) => ({ name: x.name, flags: x.tab ? SetExtensionFlag.TAB : 0 })));
        await this.refresh();
        this.msg.say(SETTINGS.SAVED, "ok");
      } catch (e) {
        this.msg.say(`${SETTINGS.SAVE_FAILED} ${errorText(e)}`, "bad");
        await this.refresh();
      }
    });
  }
  /**
   * Installs, updates or reinstalls name from the repository.
   * @param {string|null} version - the version to install, null for the latest
   */
  #fromRepository(name, version, msg) {
    this.#run(async () => {
      const existing = this.installed.find((x) => x.name === name);
      const failed = existing ? EXTENSIONS.UPDATE_FAILED : EXTENSIONS.INSTALL_FAILED;
      try {
        await this.loadList();
        if (this.listError) {
          throw new ExtensionError(this.listError);
        }
        const airfrog = this.airfrog();
        const info = await this.#readInfo(airfrog);
        const entry = this.list.get(name);
        const chosen = version ? findVersion(entry, version, info.model, info.wamr) : latest(entry, info.model, info.wamr);
        if (!chosen) {
          throw new ExtensionError(ERRORS.EXTENSION_UNSUPPORTED());
        }
        msg.say(this.#progress(existing, chosen.metadata));
        const bytes = await downloadImage(chosen.image.url);
        checkDownload(bytes, name, chosen.image);
        await this.#install(airfrog, bytes, chosen.metadata, false, msg);
      } catch (e) {
        msg.say(`${failed} ${errorText(e)}`, "bad");
      }
    });
  }
  #progress(existing, metadata) {
    const version = VALUES.VERSION(metadata.version);
    return existing ? EXTENSIONS.UPDATING(metadata.display_name, version) : EXTENSIONS.INSTALLING(metadata.display_name, version);
  }
  async #install(airfrog, image, metadata, sideLoaded, msg) {
    const existing = this.installed.find((x) => x.name === metadata.name);
    const local = sideLoaded || isLocal(this.extensionsUrl);
    const withUi = this.installed.filter((x) => x.ui).length;
    const tab = !existing && uiAddress(metadata.ui, local) && withUi < DEFAULT_TABS;
    msg.say(this.#progress(existing, metadata));
    await airfrog.installExtension(image, (tab ? ExtensionFlag.TAB : 0) | (sideLoaded ? ExtensionFlag.SIDE_LOADED : 0));
    await this.refresh();
    const version = VALUES.VERSION(metadata.version);
    msg.say(existing ? EXTENSIONS.UPDATED(metadata.display_name, version) : EXTENSIONS.INSTALLED(metadata.display_name, version), "ok");
    if (existing) {
      this.onUpdated(metadata.name);
    }
  }
  #remove(x, msg) {
    this.#run(async () => {
      msg.say(EXTENSIONS.REMOVING(x.displayName));
      try {
        await this.airfrog().removeExtension(x.name);
        await this.refresh();
        msg.say(EXTENSIONS.REMOVED(x.displayName), "ok");
      } catch (e) {
        msg.say(`${EXTENSIONS.REMOVE_FAILED} ${errorText(e)}`, "bad");
        await this.refresh();
      }
    });
  }
  /** A package was chosen with Install from file: confirm, then install it. */
  async #chosen() {
    const file = this.file.files?.[0];
    this.file.value = "";
    if (!file || this.busy) {
      return;
    }
    let pkg;
    try {
      const info = await this.#readInfo(this.airfrog());
      pkg = await readPackage(new Uint8Array(await file.arrayBuffer()), info.model, info.wamr);
    } catch (e) {
      this.msg.say(`${EXTENSIONS.INSTALL_FAILED} ${errorText(e)}`, "bad");
      return;
    }
    this.msg.say("");
    this.confirm.ask(EXTENSIONS.SIDE_LOAD_CONFIRM, EXTENSIONS.INSTALL, () => this.#run(async () => {
      const existing = this.installed.some((x) => x.name === pkg.metadata.name);
      try {
        await this.#install(this.airfrog(), pkg.image, pkg.metadata, true, this.msg);
      } catch (e) {
        const failed = existing ? EXTENSIONS.UPDATE_FAILED : EXTENSIONS.INSTALL_FAILED;
        this.msg.say(`${failed} ${errorText(e)}`, "bad");
      }
    }));
  }
};
function nameLink(m) {
  const e = /^https:\/\//.test(m.source ?? "") ? link(m.source, m.display_name, { newTab: true }) : h("span", {}, m.display_name);
  e.classList.add("name");
  return e;
}
async function downloadImage(url) {
  try {
    return await download(url, { cache: "no-store" });
  } catch (e) {
    throw new ExtensionError(downloadText(e));
  }
}

// ui/src/extensions/bridge.js
var FORWARDED2 = /* @__PURE__ */ new Set([CLAIM, RELEASE, TARGET_CMD, IDENTIFY]);
var GET_COMMANDS = new Set(Object.entries(Command).filter(([k]) => k.startsWith("GET_")).map(([, v]) => v));
function isTrusted(origin) {
  try {
    const tld = new URL(AIRFROG_TLD);
    const u = new URL(origin);
    return u.protocol === tld.protocol && u.port === tld.port && (u.hostname === tld.hostname || u.hostname.endsWith(`.${tld.hostname}`));
  } catch (e) {
    return false;
  }
}
function route(message2, name, trusted) {
  const { type, payload } = message2 ?? {};
  if (!Number.isInteger(type) || type < 0 || type > 65535 || !(payload instanceof Uint8Array)) {
    return "drop";
  }
  if (trusted || FORWARDED2.has(type)) {
    return "forward";
  }
  if (type === AIRFROG_CMD) {
    const cmd = decodeAirfrogCmd(payload);
    return cmd && GET_COMMANDS.has(cmd.command) ? "forward" : "drop";
  }
  if (type === EXT_CMD) {
    const cmd = decodeExtCmd(payload);
    if (!cmd) {
      return "drop";
    }
    return cmd.name === name ? "forward" : "not-installed";
  }
  return "drop";
}
var FrameLink = class {
  /** The id of the connection the frame wants, or null */
  #id = null;
  /** The open connection, for #id */
  #socket = null;
  /** The id of the frame's last connection request, whose heights are used after it closes */
  #heightId = null;
  #opening = false;
  #closed = false;
  /**
   * @param {object} options
   * @param {string} options.name - the extension name
   * @param {string} options.origin - the website the extension UI is loaded
   *        from
   * @param {function(): Window|null} options.target - the frame's window
   * @param {function(): Promise<import('../../../js/awp.js').AwpSocket>} options.open -
   *        opens and logs in a new connection to Airfrog
   * @param {function()} [options.onConnect] - called on each connection
   *        request from the extension UI
   * @param {function(number)} [options.onHeight] - called with the
   *        extension UI's page height in pixels, which its open connection
   *        posts
   */
  constructor({ name, origin, target, open, onConnect = () => {
  }, onHeight = () => {
  } }) {
    this.name = name;
    this.origin = origin;
    this.trusted = isTrusted(origin);
    this.target = target;
    this.open = open;
    this.onConnect = onConnect;
    this.onHeight = onHeight;
  }
  /** @param {MessageEvent} event */
  receive(event) {
    const win = this.target();
    if (this.#closed || !win || event.source !== win || event.origin !== this.origin) {
      return;
    }
    const message2 = event.data?.[EXTENSION_KEY];
    if (!message2 || typeof message2 !== "object" || typeof message2.id !== "string" || !message2.id) {
      return;
    }
    if (message2.connect) {
      this.onConnect();
      this.#request(message2.id);
      return;
    }
    if ("height" in message2) {
      if (message2.id === this.#heightId && Number.isInteger(message2.height) && message2.height >= 0) {
        this.onHeight(message2.height);
      }
      return;
    }
    if (message2.id !== this.#id) {
      return;
    }
    if (message2.close) {
      this.#id = null;
      this.#drop(Number.isInteger(message2.close.closeCode) ? message2.close.closeCode : void 0);
      return;
    }
    switch (route(message2, this.name, this.trusted)) {
      case "forward":
        try {
          this.#socket?.send(message2.type, message2.payload);
        } catch (e) {
        }
        return;
      case "not-installed":
        this.#post(this.#id, {
          type: ERROR,
          flags: HEADER_RESPONSE,
          payload: encodeError({ code: ERROR_OUT_OF_RANGE })
        });
        return;
      default:
        console.warn(`${this.name} UI: message type ${message2.type} dropped`);
    }
  }
  /** Closes the connection without posting a close: the frame is being removed or reloaded. */
  close() {
    this.#closed = true;
    this.#id = null;
    this.#heightId = null;
    this.#drop();
  }
  #post(id, message2) {
    try {
      this.target()?.postMessage({ [EXTENSION_KEY]: { ...message2, id } }, this.origin);
    } catch (e) {
    }
  }
  /** Closes the open connection, if any. */
  #drop(code) {
    const socket = this.#socket;
    this.#socket = null;
    socket?.close(code);
  }
  /**
   * A connection request with id. The connection or request it replaces
   * is closed and posted a close.
   */
  #request(id) {
    if (this.#id) {
      this.#post(this.#id, { close: errorToBridge(new AirfrogError("CLOSED")) });
    }
    this.#drop();
    this.#id = id;
    this.#heightId = id;
    if (!this.#opening) {
      this.#openWanted();
    }
  }
  /** Opens connections one at a time until the one wanted is open. */
  async #openWanted() {
    this.#opening = true;
    while (this.#id && !this.#socket && !this.#closed) {
      const id = this.#id;
      let socket;
      try {
        socket = await this.open();
      } catch (e) {
        if (this.#id === id && !this.#closed) {
          this.#id = null;
          this.#post(id, { close: errorToBridge(e instanceof AirfrogError ? e : new AirfrogError("CONNECT", e.message)) });
        }
        continue;
      }
      if (this.#id !== id || this.#closed) {
        socket.close();
        continue;
      }
      this.#attach(id, socket);
    }
    this.#opening = false;
  }
  #attach(id, socket) {
    this.#socket = socket;
    socket.onclose = (error) => {
      if (this.#socket === socket) {
        this.#socket = null;
        this.#id = null;
        this.#post(id, { close: errorToBridge(error) });
      }
    };
    this.#post(id, {
      type: HELLO,
      flags: 0,
      payload: socket.helloPayload,
      extension: this.name,
      limited: !this.trusted
    });
    socket.onmessage = (type, flags, payload) => {
      if (type === EXT_NOTIFY && decodeExtCmd(payload)?.name !== this.name) {
        return;
      }
      this.#post(id, { type, flags, payload });
    };
  }
};

// ui/src/extensions/pane.js
var LOAD_MS = 1e4;
var UNLOAD_MS = 10 * 60 * 1e3;
var SANDBOX = "allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-downloads allow-modals";
var ExtensionPane = class {
  #frame = null;
  #link = null;
  #loadTimer = null;
  #unloadTimer = null;
  /**
   * @param {object} options
   * @param {string} options.name - the extension name
   * @param {string} options.displayName
   * @param {string} options.ui - the extension UI's address, checked
   * @param {function(): Promise<object>} options.open - opens a logged-in
   *        AwpSocket to Airfrog
   * @param {{loadMs?: number, unloadMs?: number}} [options.times]
   */
  constructor({ name, displayName, ui, open, times = {} }) {
    this.name = name;
    this.displayName = displayName;
    this.ui = ui;
    this.open = open;
    this.loadMs = times.loadMs ?? LOAD_MS;
    this.unloadMs = times.unloadMs ?? UNLOAD_MS;
    this.state = "unloaded";
    this.visible = false;
    this.msg = message();
    this.holder = h("div", { class: "ext-frame" });
    this.element = h("div", { class: "ext-pane" }, this.msg, this.holder);
  }
  get loaded() {
    return this.state !== "unloaded";
  }
  /** Updates the name and address. A changed address loads the new one. */
  update(displayName, ui) {
    this.displayName = displayName;
    if (this.#frame) {
      this.#frame.title = displayName;
    }
    if (ui !== this.ui) {
      this.ui = ui;
      if (this.loaded) {
        this.reload();
      }
    }
  }
  /** The tab is displayed: loads the extension UI if it isn't loaded. */
  shown() {
    this.visible = true;
    clearTimeout(this.#unloadTimer);
    this.#unloadTimer = null;
    if (!this.loaded) {
      this.load();
    }
  }
  /** The tab is hidden: the extension UI is unloaded after UNLOAD_MS. */
  hidden() {
    if (!this.visible) {
      return;
    }
    this.visible = false;
    if (this.loaded && !this.#unloadTimer) {
      this.#unloadTimer = setTimeout(() => {
        this.#unloadTimer = null;
        this.unload();
      }, this.unloadMs);
    }
  }
  load() {
    this.unload();
    const origin = new URL(this.ui).origin;
    const frame = h("iframe", {
      src: this.ui,
      title: this.displayName,
      referrerPolicy: "no-referrer",
      hidden: true
    });
    frame.setAttribute("sandbox", SANDBOX);
    this.#frame = frame;
    this.#link = new FrameLink({
      name: this.name,
      origin,
      target: () => frame.contentWindow,
      open: this.open,
      onConnect: () => this.#connected(),
      onHeight: (height) => {
        frame.style.height = `${height}px`;
      }
    });
    this.state = "loading";
    this.msg.say(EXTENSIONS.LOADING_UI(this.displayName));
    this.#loadTimer = setTimeout(() => {
      this.#loadTimer = null;
      if (this.state === "loading") {
        this.state = "failed";
        this.msg.say(EXTENSIONS.UI_FAILED(this.displayName), "bad");
      }
    }, this.loadMs);
    this.holder.replaceChildren(frame);
  }
  unload() {
    clearTimeout(this.#loadTimer);
    clearTimeout(this.#unloadTimer);
    this.#loadTimer = null;
    this.#unloadTimer = null;
    this.#link?.close();
    this.#link = null;
    this.#frame = null;
    this.holder.replaceChildren();
    this.msg.say("");
    this.state = "unloaded";
  }
  /** Loads the extension UI again if it is loaded. */
  reload() {
    if (this.loaded) {
      this.load();
      if (!this.visible) {
        this.visible = true;
        this.hidden();
      }
    }
  }
  /** @param {MessageEvent} event - a message event of the Airfrog UI's window */
  receive(event) {
    this.#link?.receive(event);
  }
  destroy() {
    this.unload();
    this.element.remove();
  }
  #connected() {
    clearTimeout(this.#loadTimer);
    this.#loadTimer = null;
    this.state = "loaded";
    this.msg.say("");
    if (this.#frame) {
      this.#frame.hidden = false;
    }
  }
};

// ui/src/full-ui.js
function extensionTabId(name) {
  return `ext-${name}`;
}
var FullUi = class {
  /**
   * @param {object} options
   * @param {object} options.setup - Airfrog's internal JS setup module, as Airfrog serves it
   * @param {object|null} [options.firmware] - the verified firmware manifest
   * @param {string|null} [options.firmwareError] - why there isn't one
   * @param {function(): Promise<object>} [options.loadFirmware] - loads the
   *        firmware manifest to check a chosen firmware file
   * @param {function(): Promise<{url: string, manifest: object}>} options.loadExtensions -
   *        loads and verifies the extensions manifest
   * @param {string|null} options.extensionsUrl - the extensions manifest's
   *        address, or null when the Airfrog manifest didn't load
   * @param {object} [options.session]
   * @param {string} [options.version] - this full user interface's version
   */
  constructor({
    setup,
    firmware = null,
    firmwareError = null,
    loadFirmware = null,
    loadExtensions,
    extensionsUrl,
    session,
    version
  }) {
    this.login = null;
    session ??= new setup.Session(location.host, { connect: async (host, password) => {
      const airfrog = await Airfrog.connect(host, password);
      this.login = { host, password, airfrog };
      airfrog.addEventListener("close", () => {
        if (this.login?.airfrog === airfrog) {
          this.login = null;
        }
      });
      return airfrog;
    } });
    this.targetCard = new TargetCard(this);
    this.targetView = new TargetView();
    this.pinsView = new PinsView();
    this.page = new setup.Page({
      firmware,
      firmwareError,
      loadFirmware,
      session,
      tabs: [{ id: "target", name: PAGE.TARGET_TAB, element: h("div", {}, this.targetCard.element) }],
      advanced: [this.targetView.element, this.pinsView.element],
      recordTab: true,
      onRender: () => this.#rendered()
    });
    if (version) {
      this.page.setup.views.about.setUiVersion?.(versionText(version));
    }
    this.extensionPanes = /* @__PURE__ */ new Map();
    this.extensions = this.#addExtensions(loadExtensions, extensionsUrl);
  }
  #addExtensions(loadExtensions, extensionsUrl) {
    const page = this.page;
    const extensions = new ExtensionsTab({
      airfrog: () => this.session.airfrog,
      state: () => this.state,
      loadExtensions,
      extensionsUrl,
      onChange: (installed) => this.#extensionTabs(installed),
      onUpdated: (name) => this.extensionPanes.get(name)?.reload(),
      open: (name) => page.show(extensionTabId(name), true)
    });
    this.#addTab("extensions", EXTENSIONS.TAB, extensions.element);
    const show = page.show.bind(page);
    page.show = (id, record) => {
      show(id, record);
      for (const [name, pane] of this.extensionPanes) {
        if (id === extensionTabId(name)) {
          pane.shown();
        } else {
          pane.hidden();
        }
      }
      if (id === "extensions") {
        extensions.shown();
      }
    };
    window.addEventListener("message", (event) => {
      for (const pane of this.extensionPanes.values()) {
        pane.receive(event);
      }
    });
    let connections = 0;
    this.session.addEventListener("connected", async () => {
      connections += 1;
      await extensions.refresh();
      if (connections === 1 && this.page.panes[location.hash.slice(1)] && location.hash.startsWith("#ext-")) {
        page.show(location.hash.slice(1));
      }
      if (connections > 1) {
        for (const pane of this.extensionPanes.values()) {
          pane.reload();
        }
      }
    });
    if (location.hash === "#extensions") {
      page.show("extensions");
    }
    return extensions;
  }
  /** Adds a tab after Advanced, or before beforeId. */
  #addTab(id, name, element, beforeId = null) {
    const page = this.page;
    page.panes[id] = element;
    element.hidden = true;
    page.tabButtons[id] = h("button", {
      type: "button",
      role: "tab",
      "aria-selected": "false",
      onclick: () => page.show(id, true)
    }, name);
    page.tabs.firstChild.insertBefore(page.tabButtons[id], beforeId ? page.tabButtons[beforeId] : null);
    page.content.append(element);
  }
  #removeTab(id) {
    const page = this.page;
    const shown = !page.panes[id].hidden;
    page.panes[id].remove();
    page.tabButtons[id].remove();
    delete page.panes[id];
    delete page.tabButtons[id];
    if (shown) {
      page.show("extensions", true);
    }
  }
  /**
   * Makes the extension UI tabs match the installed extensions: one for
   * each with a UI, in list order, with its button displayed while its
   * Tab checkbox is ticked.
   */
  #extensionTabs(installed) {
    const withUi = installed.filter((x) => x.ui);
    for (const name of [...this.extensionPanes.keys()]) {
      if (!withUi.some((x) => x.name === name)) {
        this.extensionPanes.get(name).destroy();
        this.extensionPanes.delete(name);
        this.#removeTab(extensionTabId(name));
      }
    }
    for (const x of withUi) {
      const id = extensionTabId(x.name);
      let pane = this.extensionPanes.get(x.name);
      if (pane) {
        pane.update(x.displayName, x.ui);
        this.page.tabButtons[id].textContent = x.displayName;
      } else {
        pane = new ExtensionPane({
          name: x.name,
          displayName: x.displayName,
          ui: x.ui,
          open: () => this.#openSocket()
        });
        this.extensionPanes.set(x.name, pane);
        this.#addTab(id, x.displayName, pane.element, "target");
      }
      const tabButton = this.page.tabButtons[id];
      tabButton.hidden = !x.tab;
      this.page.tabs.firstChild.insertBefore(tabButton, this.page.tabButtons.target);
    }
  }
  /** A new logged-in connection for an extension UI. */
  #openSocket() {
    if (!this.login || this.login.airfrog.isClosed()) {
      return Promise.reject(new AirfrogError("CLOSED"));
    }
    return AwpSocket.open(this.login.host, this.login.password);
  }
  get session() {
    return this.page.session;
  }
  get state() {
    return this.page.state;
  }
  /** Replaces body's contents with the page and connects. */
  start(body = document.body) {
    this.page.start(body);
  }
  render() {
    this.page.render();
  }
  /** Whether the Target card has an operation on the target running. */
  targetBusy() {
    return Boolean(this.targetCard.busy);
  }
  #rendered() {
    this.targetCard.update(this.state);
    this.targetView.update(this.state);
    this.pinsView.update(this.state);
  }
};

// build/ui-deps/noble/node_modules/@noble/ed25519/index.js
var freeze = Object.freeze;
var P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn;
var N = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
var _d = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n;
var Gx = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an;
var Gy = 0x6666666666666666666666666666666666666666666666666666666666666658n;
var _a = P - 1n;
var ed25519_CURVE = freeze({
  p: P,
  n: N,
  h: 8n,
  a: _a,
  d: _d,
  Gx,
  Gy
});
var LEN = 32;
var isBytes = (a) => {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && a.BYTES_PER_ELEMENT === 1;
};
var abytes = (value, length, title = "") => {
  if (isBytes(value) && (length === void 0 || value.length === length))
    return value;
  const bytes = isBytes(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message2 = (title ? `"${title}" ` : "") + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message2);
  throw new RangeError(message2);
};
var snapshotBytes = (value, title = "", length) => Uint8Array.from(abytes(value, length, title));
var padh = (n, pad) => n.toString(16).padStart(pad, "0");
var bytesToHex = (bytes) => {
  let hex3 = "";
  for (const byte of abytes(bytes))
    hex3 += padh(byte, 2);
  return hex3;
};
var hexToBytes = (hex3) => {
  const e = "hex invalid";
  if (typeof hex3 !== "string")
    throw new TypeError(e);
  if (hex3.length % 2 || !/^[\da-f]*$/i.test(hex3))
    throw new RangeError(e);
  const array = new Uint8Array(hex3.length / 2);
  for (let ai = 0, hi = 0; ai < array.length; ai++, hi += 2) {
    const n1 = hex3.charCodeAt(hi);
    const n2 = hex3.charCodeAt(hi + 1);
    array[ai] = ((n1 & 15) + (n1 >> 6) * 9) * 16 + (n2 & 15) + (n2 >> 6) * 9;
  }
  return array;
};
var concatBytes = (...arrays) => {
  let sum = 0;
  for (const a of arrays)
    sum += abytes(a).length;
  const res = new Uint8Array(sum);
  let pad = 0;
  for (const a of arrays) {
    res.set(a, pad);
    pad += a.length;
  }
  return res;
};
var arange = (n, min, max, msg = "bad number: out of range") => {
  if (typeof n !== "bigint")
    throw new TypeError(msg);
  if (min <= n && n < max)
    return n;
  throw new RangeError(msg);
};
var mod = (a, b = P) => (a %= b) >= 0n ? a : b + a;
var P_MASK = (1n << 255n) - 1n;
var modP = (num) => {
  if (num < 0n)
    throw new RangeError("negative coordinate");
  let r = (num >> 255n) * 19n + (num & P_MASK);
  r = (r >> 255n) * 19n + (r & P_MASK);
  return r % P;
};
var modN = (a) => mod(a, N);
var invert = (number, modulo) => {
  if (number === 0n)
    throw new Error("invert: expected non-zero number");
  if (modulo <= 1n)
    throw new Error("invert: expected modulus > 1, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x = 0n, u = 1n;
  while (a !== 0n) {
    const q = b / a;
    const r = b - a * q;
    const m = x - u * q;
    b = a, a = r, x = u, u = m;
  }
  const gcd = b;
  if (gcd !== 1n)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
};
var _hash = (name) => {
  const fn = hashes[name];
  if (typeof fn !== "function")
    throw new Error("hashes." + name + " not set");
  return fn;
};
var callHash = (name, ...m) => abytes(_hash(name)(concatBytes(...m)), 64, "digest");
var apoint = (p) => {
  if (p instanceof Point)
    return p;
  throw new TypeError("Point expected");
};
var B256 = 2n ** 256n;
var Point = class _Point {
  static BASE;
  static ZERO;
  X;
  Y;
  Z;
  T;
  // Constructor only bounds-checks and freezes XYZT coordinates; it does not prove the point is
  // on-curve or that T matches X*Y/Z.
  constructor(X, Y, Z, T) {
    const max = B256;
    this.X = arange(X, 0n, max);
    this.Y = arange(Y, 0n, max);
    this.Z = arange(Z, 1n, max);
    this.T = arange(T, 0n, max);
    freeze(this);
  }
  static CURVE() {
    return ed25519_CURVE;
  }
  static fromAffine(p) {
    return new _Point(p.x, p.y, 1n, modP(p.x * p.y));
  }
  /** RFC8032 5.1.3: Uint8Array to Point. */
  static fromBytes(bytes, zip215 = false) {
    const normed = snapshotBytes(bytes, "point", LEN);
    const lastByte = normed[31];
    normed[31] = lastByte & ~128;
    const y = bytesToNumberLE(normed);
    if (!zip215)
      arange(y, 0n, P);
    const y2 = modP(y * y);
    const u = mod(y2 - 1n);
    const v = modP(_d * y2 + 1n);
    let { isValid, value: x } = uvRatio(u, v);
    if (!isValid)
      throw new Error("bad point: y not sqrt");
    const isLastByteOdd = !!(lastByte & 128);
    if (!zip215 && x === 0n && isLastByteOdd)
      throw new Error("bad point: x==0, isLastByteOdd");
    if (isLastByteOdd !== !!(x & 1n))
      x = mod(-x);
    return new _Point(x, y, 1n, modP(x * y));
  }
  static fromHex(hex3, zip215) {
    return _Point.fromBytes(hexToBytes(hex3), zip215);
  }
  get x() {
    return this.toAffine().x;
  }
  get y() {
    return this.toAffine().y;
  }
  /** Checks if the point is valid and on-curve. */
  assertValidity() {
    const a = _a;
    const d = _d;
    const p = this;
    if (p.is0())
      throw new Error("bad point: ZERO");
    const { X, Y, Z, T } = p;
    const X2 = modP(X * X);
    const Y2 = modP(Y * Y);
    const Z2 = modP(Z * Z);
    const Z4 = modP(Z2 * Z2);
    const aX2 = modP(X2 * a);
    const left = modP(Z2 * (aX2 + Y2));
    const right = mod(Z4 + modP(d * modP(X2 * Y2)));
    if (left !== right)
      throw new Error("bad point: equation left != right (1)");
    const XY = modP(X * Y);
    const ZT = modP(Z * T);
    if (XY !== ZT)
      throw new Error("bad point: equation left != right (2)");
    return this;
  }
  /** Equality check: compare points P&Q. */
  equals(other) {
    const { X: X1, Y: Y1, Z: Z1 } = this;
    const { X: X2, Y: Y2, Z: Z2 } = apoint(other);
    return modP(X1 * Z2) === modP(X2 * Z1) && modP(Y1 * Z2) === modP(Y2 * Z1);
  }
  is0() {
    return this.equals(I);
  }
  /** Flip point over y coordinate. */
  negate() {
    return new _Point(mod(-this.X), this.Y, this.Z, mod(-this.T));
  }
  /** Point doubling. Complete formula. Cost: `4M + 4S + 1*a + 6add + 1*2`. */
  double() {
    const { X: X1, Y: Y1, Z: Z1 } = this;
    const a = _a;
    const A = modP(X1 * X1);
    const B = modP(Y1 * Y1);
    const C = modP(2n * Z1 * Z1);
    const D = modP(a * A);
    const x1y1 = mod(X1 + Y1);
    const E = mod(modP(x1y1 * x1y1) - A - B);
    const G2 = mod(D + B);
    const F = mod(G2 - C);
    const H = mod(D - B);
    const X3 = modP(E * F);
    const Y3 = modP(G2 * H);
    const T3 = modP(E * H);
    const Z3 = modP(F * G2);
    return new _Point(X3, Y3, Z3, T3);
  }
  /** Point addition. Complete formula. Cost: `9M + 1*a + 1*d + 7add`. */
  add(other) {
    const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
    const { X: X2, Y: Y2, Z: Z2, T: T2 } = apoint(other);
    const a = _a;
    const d = _d;
    const A = modP(X1 * X2);
    const B = modP(Y1 * Y2);
    const C = modP(modP(T1 * d) * T2);
    const D = modP(Z1 * Z2);
    const E = mod(modP(mod(X1 + Y1) * mod(X2 + Y2)) - A - B);
    const F = mod(D - C);
    const G2 = mod(D + C);
    const H = mod(B - modP(a * A));
    const X3 = modP(E * F);
    const Y3 = modP(G2 * H);
    const T3 = modP(E * H);
    const Z3 = modP(F * G2);
    return new _Point(X3, Y3, Z3, T3);
  }
  subtract(other) {
    return this.add(apoint(other).negate());
  }
  /**
   * Point-by-scalar multiplication. Safe mode requires `1 <= n < CURVE.n`.
   * Unsafe mode additionally permits `n = 0` and returns the identity point for that case.
   * Uses {@link wNAF} for base point.
   * Uses fake point to mitigate side-channel leakage.
   * @param n - scalar by which point is multiplied
   * @param safe - safe mode guards against timing attacks; unsafe mode is faster
   */
  multiply(n, safe = true) {
    if (!safe && n === 0n)
      return I;
    arange(n, 1n, N);
    if (!safe && this.is0())
      return I;
    if (n === 1n)
      return this;
    if (this.equals(G))
      return wNAF(n).p;
    let p = I;
    let f = G;
    let d = this;
    for (let i = 0; safe ? i < 256 : n > 0n; i++) {
      if (n & 1n)
        p = p.add(d);
      else if (safe)
        f = f.add(d);
      d = d.double();
      n >>= 1n;
    }
    return p;
  }
  multiplyUnsafe(scalar) {
    return this.multiply(scalar, false);
  }
  /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
  toAffine() {
    const { X, Y, Z } = this;
    if (this.equals(I))
      return { x: 0n, y: 1n };
    const iz = invert(Z, P);
    if (modP(Z * iz) !== 1n)
      throw new Error("invalid inverse");
    return { x: modP(X * iz), y: modP(Y * iz) };
  }
  toBytes() {
    const { x, y } = this.toAffine();
    const b = numTo32bLE(y);
    b[31] |= x & 1n ? 128 : 0;
    return b;
  }
  toHex() {
    return bytesToHex(this.toBytes());
  }
  clearCofactor() {
    return this.multiply(8n, false);
  }
  isSmallOrder() {
    return this.clearCofactor().is0();
  }
  isTorsionFree() {
    return this.multiply(N / 2n, false).double().add(this).is0();
  }
};
var G = new Point(Gx, Gy, 1n, mod(Gx * Gy));
var I = new Point(0n, 1n, 1n, 0n);
Point.BASE = G;
Point.ZERO = I;
var numTo32bLE = (num) => hexToBytes(padh(arange(num, 0n, B256), 64)).reverse();
var bytesToNumberLE = (b) => BigInt("0x" + bytesToHex(Uint8Array.from(abytes(b)).reverse()));
var pow2 = (x, power) => {
  let r = x;
  while (power-- > 0) {
    r = modP(r * r);
  }
  return r;
};
var pow_2_252_3 = (x) => {
  const x2 = modP(x * x);
  const b2 = modP(x2 * x);
  const b4 = modP(pow2(b2, 2) * b2);
  const b5 = modP(pow2(b4, 1) * x);
  const b10 = modP(pow2(b5, 5) * b5);
  const b20 = modP(pow2(b10, 10) * b10);
  const b40 = modP(pow2(b20, 20) * b20);
  const b80 = modP(pow2(b40, 40) * b40);
  const b160 = modP(pow2(b80, 80) * b80);
  const b240 = modP(pow2(b160, 80) * b80);
  const b250 = modP(pow2(b240, 10) * b10);
  return modP(pow2(b250, 2) * x);
};
var RM1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n;
var uvRatio = (u, v) => {
  const v3 = modP(v * modP(v * v));
  const v7 = modP(modP(v3 * v3) * v);
  const pow = pow_2_252_3(modP(u * v7));
  let x = modP(u * modP(v3 * pow));
  const vx2 = modP(v * modP(x * x));
  const root1 = x;
  const root2 = modP(x * RM1);
  const useRoot1 = vx2 === u;
  const useRoot2 = vx2 === mod(-u);
  const noRoot = vx2 === mod(-u * RM1);
  if (useRoot1)
    x = root1;
  if (useRoot2 || noRoot)
    x = root2;
  if ((mod(x) & 1n) === 1n)
    x = mod(-x);
  return { isValid: useRoot1 || useRoot2, value: x };
};
var modL_LE = (hash) => modN(bytesToNumberLE(hash));
var hashFinishSync = (res) => res[1](callHash("sha512", res[0]));
var getZip215 = (options) => {
  if (options === null || typeof options !== "object")
    throw new TypeError("expected valid options object");
  return options.zip215 ?? true;
};
var _verify = (sig, msg, publicKey, options) => {
  sig = abytes(sig, 64, "signature");
  msg = abytes(msg, void 0, "message");
  publicKey = abytes(publicKey, LEN, "publicKey");
  const zip215 = getZip215(options);
  const r = sig.subarray(0, LEN);
  const s = bytesToNumberLE(sig.subarray(LEN, 64));
  let A, R, SB;
  let hashable = Uint8Array.of();
  let finished = false;
  try {
    A = Point.fromBytes(publicKey, zip215);
    R = Point.fromBytes(r, zip215);
    SB = G.multiply(s, false);
    hashable = concatBytes(r, publicKey, msg);
    finished = true;
  } catch (error) {
  }
  const finish = (hashed) => {
    if (!finished)
      return false;
    if (!zip215 && A.isSmallOrder())
      return false;
    const k = modL_LE(hashed);
    const RkA = R.add(A.multiply(k, false));
    return RkA.subtract(SB).clearCofactor().is0();
  };
  return [hashable, finish];
};
var verify = (signature, message2, publicKey, opts = {}) => hashFinishSync(_verify(signature, message2, publicKey, opts));
var hashes = {
  sha512Async: async (message2) => {
    const s = globalThis?.crypto?.subtle;
    if (!s)
      throw new Error("crypto.subtle must be defined, consider polyfill");
    return new Uint8Array(await s.digest("SHA-512", concatBytes(message2)));
  },
  sha512: void 0
};
var precompute = () => {
  const points = [];
  let p = G;
  let b;
  for (let w = 0; w < 33; w++) {
    b = p;
    points.push(b);
    for (let i = 1; i < 128; i++) {
      b = b.add(p);
      points.push(b);
    }
    p = b.double();
  }
  return points;
};
var Gpows = void 0;
var ctneg = (cnd, p) => {
  const n = p.negate();
  return cnd ? n : p;
};
var wNAF = (n) => {
  const comp = Gpows || (Gpows = precompute());
  let p = I;
  let f = G;
  for (let w = 0; w < 33; w++) {
    let wbits = Number(n & 255n);
    n >>= 8n;
    if (wbits > 128) {
      wbits -= 256;
      n += 1n;
    }
    const off = w * 128;
    const offP = off + Math.abs(wbits) - 1;
    const isOddW = w % 2 !== 0;
    const isNeg = wbits < 0;
    if (wbits === 0) {
      f = f.add(ctneg(isOddW, comp[off]));
    } else {
      p = p.add(ctneg(isNeg, comp[offP]));
    }
  }
  if (n !== 0n)
    throw new Error("invalid wnaf");
  return { p, f };
};

// build/ui-deps/noble/node_modules/@noble/hashes/_u64.js
var U32_MASK64 = /* @__PURE__ */ (() => BigInt(2 ** 32 - 1))();
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h: h2, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h2, l];
  }
  return [Ah, Al];
}
var fromNumH = (n) => n / 2 ** 32 | 0;
var fromNumL = (n) => n >>> 0;
function setU64FromNum(view, byteOffset, n, isLE) {
  const h2 = fromNumH(n);
  const l = fromNumL(n);
  view.setUint32(byteOffset, isLE ? l : h2, isLE);
  view.setUint32(byteOffset + 4, isLE ? h2 : l, isLE);
}
var shrSH = (h2, _l, s) => h2 >>> s;
var shrSL = (h2, l, s) => h2 << 32 - s | l >>> s;
var rotrSH = (h2, l, s) => h2 >>> s | l << 32 - s;
var rotrSL = (h2, l, s) => h2 << 32 - s | l >>> s;
var rotrBH = (h2, l, s) => h2 << 64 - s | l >>> s - 32;
var rotrBL = (h2, l, s) => h2 >>> s - 32 | l << 64 - s;
function add(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}
var add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
var add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
var add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
var add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
var add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
var add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;

// build/ui-deps/noble/node_modules/@noble/hashes/utils.js
function isBytes2(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle = (title) => title ? `"${title}" ` : "";
function anumber(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
  return n;
}
function abytes2(value, length, title = "") {
  if (isBytes2(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber(length, "length");
  const bytes = isBytes2(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message2 = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message2);
  throw new RangeError(message2);
}
var aobject = (value, label) => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
};
var aopts = (value, label) => {
  aobject(value, label);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null)
    throw new TypeError(`"${label}" expected plain object`);
  if (Object.hasOwn(value, "__proto__"))
    throw new TypeError(`"${label}.__proto__" is not allowed`);
};
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("hash was destroyed");
  if (checkFinished && instance.finished)
    throw new Error("digest() was already called");
}
function aoutput(out, instance) {
  abytes2(out, void 0, "output");
  const min = instance.outputLen;
  if (!(out.length >= min)) {
    throw new RangeError('"output" expected length >= ' + min);
  }
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function checkOpts(defaults, opts, title = "opts") {
  aopts(defaults, "defaults");
  if (opts !== void 0)
    aopts(opts, title);
  const merged = Object.assign(/* @__PURE__ */ Object.create(null), defaults, opts);
  return merged;
}
function createHasher(hashCons, info = {}) {
  if (typeof hashCons !== "function")
    throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
  info = checkOpts({}, info, "info");
  const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.canXOF = tmp.canXOF;
  hashC.create = (opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
var oidNist = (suffix) => ({
  // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
  // Larger suffix values would need base-128 OID encoding and a different length byte.
  oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
});

// build/ui-deps/noble/node_modules/@noble/hashes/_md.js
var HashMD = class {
  blockLen;
  outputLen;
  canXOF = false;
  padOffset;
  isLE;
  // For partial updates less than block size
  buffer;
  view;
  finished = false;
  length = 0;
  pos = 0;
  destroyed = false;
  constructor(blockLen, outputLen, padOffset, isLE) {
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    abytes2(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    let processed = false;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        processed = true;
        continue;
      }
      buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
        processed = true;
      }
    }
    this.length += data.length;
    if (processed)
      this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    buffer.fill(0, pos);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      buffer.fill(0);
    }
    setU64FromNum(view, blockLen - 8, this.length * 8, isLE);
    this.process(view, 0);
    this.roundClean();
    const oview = out === buffer ? view : createView(out);
    const len = this.outputLen;
    const outLen = len / 4;
    const state = this.get();
    if (len % 4 || outLen > state.length)
      throw new Error("invalid outputLen");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneIntoMeta(to) {
    const { buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (pos)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA512_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  4089235720,
  3144134277,
  2227873595,
  1013904242,
  4271175723,
  2773480762,
  1595750129,
  1359893119,
  2917565137,
  2600822924,
  725511199,
  528734635,
  4215389547,
  1541459225,
  327033209
]);

// build/ui-deps/noble/node_modules/@noble/hashes/sha2.js
var K512 = /* @__PURE__ */ (() => split([
  "0x428a2f98d728ae22",
  "0x7137449123ef65cd",
  "0xb5c0fbcfec4d3b2f",
  "0xe9b5dba58189dbbc",
  "0x3956c25bf348b538",
  "0x59f111f1b605d019",
  "0x923f82a4af194f9b",
  "0xab1c5ed5da6d8118",
  "0xd807aa98a3030242",
  "0x12835b0145706fbe",
  "0x243185be4ee4b28c",
  "0x550c7dc3d5ffb4e2",
  "0x72be5d74f27b896f",
  "0x80deb1fe3b1696b1",
  "0x9bdc06a725c71235",
  "0xc19bf174cf692694",
  "0xe49b69c19ef14ad2",
  "0xefbe4786384f25e3",
  "0x0fc19dc68b8cd5b5",
  "0x240ca1cc77ac9c65",
  "0x2de92c6f592b0275",
  "0x4a7484aa6ea6e483",
  "0x5cb0a9dcbd41fbd4",
  "0x76f988da831153b5",
  "0x983e5152ee66dfab",
  "0xa831c66d2db43210",
  "0xb00327c898fb213f",
  "0xbf597fc7beef0ee4",
  "0xc6e00bf33da88fc2",
  "0xd5a79147930aa725",
  "0x06ca6351e003826f",
  "0x142929670a0e6e70",
  "0x27b70a8546d22ffc",
  "0x2e1b21385c26c926",
  "0x4d2c6dfc5ac42aed",
  "0x53380d139d95b3df",
  "0x650a73548baf63de",
  "0x766a0abb3c77b2a8",
  "0x81c2c92e47edaee6",
  "0x92722c851482353b",
  "0xa2bfe8a14cf10364",
  "0xa81a664bbc423001",
  "0xc24b8b70d0f89791",
  "0xc76c51a30654be30",
  "0xd192e819d6ef5218",
  "0xd69906245565a910",
  "0xf40e35855771202a",
  "0x106aa07032bbd1b8",
  "0x19a4c116b8d2d0c8",
  "0x1e376c085141ab53",
  "0x2748774cdf8eeb99",
  "0x34b0bcb5e19b48a8",
  "0x391c0cb3c5c95a63",
  "0x4ed8aa4ae3418acb",
  "0x5b9cca4f7763e373",
  "0x682e6ff3d6b2b8a3",
  "0x748f82ee5defb2fc",
  "0x78a5636f43172f60",
  "0x84c87814a1f0ab72",
  "0x8cc702081a6439ec",
  "0x90befffa23631e28",
  "0xa4506cebde82bde9",
  "0xbef9a3f7b2c67915",
  "0xc67178f2e372532b",
  "0xca273eceea26619c",
  "0xd186b8c721c0c207",
  "0xeada7dd6cde0eb1e",
  "0xf57d4f7fee6ed178",
  "0x06f067aa72176fba",
  "0x0a637dc5a2c898a6",
  "0x113f9804bef90dae",
  "0x1b710b35131c471b",
  "0x28db77f523047d84",
  "0x32caab7b40c72493",
  "0x3c9ebe0a15c9bebc",
  "0x431d67c49c100d4c",
  "0x4cc5d4becb3e42b6",
  "0x597f299cfc657e2a",
  "0x5fcb6fab3ad6faec",
  "0x6c44198c4a475817"
].map((n) => BigInt(n))))();
var SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
var SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
var SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
var SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
var SHA2_64B = class extends HashMD {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  // h -- high 32 bits, l -- low 32 bits
  // Numeric initializers matter: starting the fields as `undefined` changes
  // V8's field representation and slows hashing down (measured on sha256).
  Ah = 0;
  Al = 0;
  Bh = 0;
  Bl = 0;
  Ch = 0;
  Cl = 0;
  Dh = 0;
  Dl = 0;
  Eh = 0;
  El = 0;
  Fh = 0;
  Fl = 0;
  Gh = 0;
  Gl = 0;
  Hh = 0;
  Hl = 0;
  constructor(outputLen, IV) {
    super(128, outputLen, 16, false);
    this.Ah = IV[0] | 0;
    this.Al = IV[1] | 0;
    this.Bh = IV[2] | 0;
    this.Bl = IV[3] | 0;
    this.Ch = IV[4] | 0;
    this.Cl = IV[5] | 0;
    this.Dh = IV[6] | 0;
    this.Dl = IV[7] | 0;
    this.Eh = IV[8] | 0;
    this.El = IV[9] | 0;
    this.Fh = IV[10] | 0;
    this.Fl = IV[11] | 0;
    this.Gh = IV[12] | 0;
    this.Gl = IV[13] | 0;
    this.Hh = IV[14] | 0;
    this.Hl = IV[15] | 0;
  }
  // prettier-ignore
  get() {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
  }
  // prettier-ignore
  set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
    this.Ah = Ah | 0;
    this.Al = Al | 0;
    this.Bh = Bh | 0;
    this.Bl = Bl | 0;
    this.Ch = Ch | 0;
    this.Cl = Cl | 0;
    this.Dh = Dh | 0;
    this.Dl = Dl | 0;
    this.Eh = Eh | 0;
    this.El = El | 0;
    this.Fh = Fh | 0;
    this.Fl = Fl | 0;
    this.Gh = Gh | 0;
    this.Gl = Gl | 0;
    this.Hh = Hh | 0;
    this.Hl = Hl | 0;
  }
  _cloneInto(to) {
    (to ||= new this.constructor()).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4) {
      SHA512_W_H[i] = view.getUint32(offset);
      SHA512_W_L[i] = view.getUint32(offset += 4);
    }
    for (let i = 16; i < 80; i++) {
      const W15h = SHA512_W_H[i - 15] | 0;
      const W15l = SHA512_W_L[i - 15] | 0;
      const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
      const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
      const W2h = SHA512_W_H[i - 2] | 0;
      const W2l = SHA512_W_L[i - 2] | 0;
      const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
      const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
      const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
      const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
      SHA512_W_H[i] = SUMh | 0;
      SHA512_W_L[i] = SUMl | 0;
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    for (let i = 0; i < 80; i++) {
      const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
      const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
      const CHIh = Eh & Fh ^ ~Eh & Gh;
      const CHIl = El & Fl ^ ~El & Gl;
      const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
      const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
      const T1l = T1ll | 0;
      const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
      const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
      const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
      const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
      Hh = Gh | 0;
      Hl = Gl | 0;
      Gh = Fh | 0;
      Gl = Fl | 0;
      Fh = Eh | 0;
      Fl = El | 0;
      ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
      Dh = Ch | 0;
      Dl = Cl | 0;
      Ch = Bh | 0;
      Cl = Bl | 0;
      Bh = Ah | 0;
      Bl = Al | 0;
      const All = add3L(T1l, sigma0l, MAJl);
      Ah = add3H(All, T1h, sigma0h, MAJh);
      Al = All | 0;
    }
    ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
    ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
    ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
    ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
    ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
    ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
    ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
    ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
  }
  roundClean() {
    clean(SHA512_W_H, SHA512_W_L);
  }
  destroy() {
    this.destroyed = true;
    clean(this.buffer);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
};
var _SHA512 = class extends SHA2_64B {
  constructor() {
    super(64, SHA512_IV);
  }
};
var sha512 = /* @__PURE__ */ createHasher(
  () => new _SHA512(),
  /* @__PURE__ */ oidNist(3)
);

// commissioning/manifest-key.js
var MANIFEST_KEY = "c44615e017975c65c1248565a67a4918e315aeab4fc0a67189b0f04692c6f85d";
var AIRFROG_MANIFEST = "https://meta.piers.rocks/airfrog/manifest.json";

// ui/src/manifests.js
hashes.sha512 = sha512;
var FIRMWARE_WORDS = {
  signature: HOME_PAGE.RELEASE_LIST_SIGNATURE,
  invalid: HOME_PAGE.RELEASE_LIST_INVALID
};
var MANIFEST_WORDS = {
  signature: HOME_PAGE.MANIFEST_SIGNATURE,
  invalid: HOME_PAGE.MANIFEST_INVALID
};
var ManifestError = class extends Error {
  constructor(message2, detail = null) {
    super(message2);
    if (detail) {
      console.warn(`Airfrog's full user interface: ${detail}`);
    }
  }
};
var isText2 = (v) => typeof v === "string" && v !== "";
function fromHex(s) {
  return new Uint8Array(s.match(/../g).map((b) => parseInt(b, 16)));
}
async function fetched(url) {
  try {
    return await download(url, { cache: "no-store" });
  } catch (e) {
    throw new ManifestError(downloadText(e), `${url}: ${e.message}`);
  }
}
function signedBy(minisig, body, key) {
  let signature;
  try {
    const line = new TextDecoder().decode(minisig).split("\n")[1];
    signature = Uint8Array.from(atob(line.trim()), (c) => c.charCodeAt(0));
  } catch (e) {
    return false;
  }
  try {
    return signature.length === 74 && signature[0] === 69 && signature[1] === 100 && verify(signature.subarray(10), body, fromHex(key));
  } catch (e) {
    return false;
  }
}
function complete(m, type) {
  if (!Number.isInteger(m.version)) {
    return false;
  }
  if (type === "airfrog") {
    return isText2(m.ui_manifest) && isText2(m.firmware_manifest) && isText2(m.support_firmware_manifest) && isText2(m.cli_manifest) && isText2(m.extensions_manifest) && isText2(m.js_library) && m.js_library.endsWith("/");
  }
  if (type === "extensions") {
    return typeof m.extensions === "object" && m.extensions !== null && !Array.isArray(m.extensions);
  }
  return true;
}
var Manifests = class {
  /** The extensions manifest's address, from the Airfrog manifest once it loads, or null. */
  extensionsUrl = null;
  #airfrog = null;
  #firmware = null;
  #extensions = null;
  /**
   * @param {object} [options]
   * @param {string} [options.url] - the Airfrog manifest's address
   * @param {string} [options.key] - the manifest key's public half in hex
   */
  constructor({ url = AIRFROG_MANIFEST, key = MANIFEST_KEY } = {}) {
    this.url = url;
    this.key = key;
  }
  /** The Airfrog manifest, loaded once, and again after a failure. */
  airfrog() {
    this.#airfrog ??= this.#manifestAt(this.url, "airfrog").then((m) => {
      this.extensionsUrl = m.extensions_manifest;
      return m;
    }).catch((e) => {
      this.#airfrog = null;
      throw e;
    });
    return this.#airfrog;
  }
  /** The firmware manifest, loaded once, and again after a failure. */
  firmware() {
    this.#firmware ??= this.airfrog().then((a) => this.#manifestAt(a.firmware_manifest, "firmware")).catch((e) => {
      this.#firmware = null;
      throw e;
    });
    return this.#firmware;
  }
  /**
   * The extensions manifest, loaded on each call. A call while one loads
   * receives that load's result.
   * @returns {Promise<{url: string, manifest: object}>}
   */
  extensions() {
    this.#extensions ??= (async () => {
      try {
        const url = (await this.airfrog()).extensions_manifest;
        return { url, manifest: await this.#manifestAt(url, "extensions") };
      } finally {
        this.#extensions = null;
      }
    })();
    return this.#extensions;
  }
  /** Fetches the manifest of type at url and its signature file, url.minisig, and verifies them. */
  async #manifestAt(url, type) {
    if (!this.key) {
      throw new ManifestError(COMMISSIONING_FIRMWARE.MANIFEST_KEY_NOT_SET);
    }
    const words = type === "firmware" ? FIRMWARE_WORDS : MANIFEST_WORDS;
    const fresh = `?t=${Date.now()}`;
    const [body, minisig] = await Promise.all([fetched(url + fresh), fetched(`${url}.minisig${fresh}`)]);
    if (!signedBy(minisig, body, this.key)) {
      throw new ManifestError(words.signature, url);
    }
    let manifest;
    try {
      manifest = JSON.parse(new TextDecoder().decode(body));
    } catch (e) {
      throw new ManifestError(words.invalid, `${url}: ${e.message}`);
    }
    if (manifest?.type !== type) {
      throw new ManifestError(words.invalid, `${url} isn't a ${type} manifest`);
    }
    if (!complete(manifest, type)) {
      throw new ManifestError(words.invalid, `${url} is missing a field`);
    }
    return manifest;
  }
};

// ui/src/main.js
var VERSION = true ? "0.1.0" : void 0;
var SETUP_API = 2;
async function start({}) {
  const setup = await import(new URL("/setup.js", location.href).href);
  if (!(setup.API >= SETUP_API)) {
    const error = new Error(HOME_PAGE.NEWER_FIRMWARE);
    error.tab = "system";
    throw error;
  }
  setup.addStyle();
  document.head.append(h("style", {}, UI_CSS));
  if (location.hash.startsWith("#bridge=")) {
    document.title = location.hostname;
    const container = h("section", { class: "card" });
    document.body.replaceChildren(
      h("div", { class: "bar" }, h(
        "div",
        { class: "bar-in" },
        h("img", { src: "/logo.png", alt: AIRFROG }),
        h("div", { class: "host" }, location.hostname)
      )),
      h("main", {}, container)
    );
    await startBridge(container);
    return;
  }
  const manifests = new Manifests();
  let firmware = null;
  let firmwareError = null;
  try {
    firmware = await manifests.firmware();
  } catch (e) {
    firmwareError = e.message;
  }
  new FullUi({
    setup,
    firmware,
    firmwareError,
    loadFirmware: () => manifests.firmware(),
    loadExtensions: () => manifests.extensions(),
    extensionsUrl: manifests.extensionsUrl,
    version: VERSION
  }).start();
}
export {
  start
};
/*! Bundled license information:

@noble/ed25519/index.js:
  (*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) *)
*/
/*
@noble/ed25519 3.2.0

The MIT License (MIT)

Copyright (c) 2019 Paul Miller (https://paulmillr.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

@noble/hashes 2.4.0

The MIT License (MIT)

Copyright (c) 2022 Paul Miller (https://paulmillr.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
