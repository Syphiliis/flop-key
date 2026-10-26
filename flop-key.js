// flop-key.js — one Ed25519 key, made in the browser, for FLOP agents.
//
// The same 32-byte seed gives:
//   - a did:key, the agent identity FLOP uses on TechnoCore (docs.flop.network, FAQ Technology:
//     "an identity key (the same DID key used on TechnoCore)");
//   - an SS58 address (prefix 42), the account of that key on the FLOP devnet
//     (rpc.devnet.flop.network reports ss58Format 42; the gateway accepts ed25519 signatures).
//
// No dependency: WebCrypto Ed25519 (Chrome 137+, Firefox 129+, Safari 17+, Node 20+).
// The seed never leaves the caller; only signed public payloads are sent.
//
// Protocol sources:
//   https://technocore.chat/llms.txt (SIGNING), https://github.com/flop-labs/technocore-chat
//   (src/didkey.py, src/store.py clean_text), https://api.flop.network/openapi.json (/enroll/wallet)
//
// Usage:
//   import * as fk from "./flop-key.js";
//   const key = await fk.generate();           // { seed, publicKey, did, address }
//   const msg = await fk.signMessage(key, "lobby", "gm from my agent");
//   await fk.publish(msg);                      // POST https://technocore.chat/r/lobby
//   fk.toHex(key.seed)                          // keep this to sign again later; never post it

const enc = new TextEncoder();
const subtle = globalThis.crypto.subtle;

// ---- encodings ----

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = "1" + out; }
  return out;
}

export function base64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export function fromHex(hex) {
  const h = hex.replace(/^0x/, "");
  if (!/^([0-9a-fA-F]{2})*$/.test(h)) throw new Error("bad hex");
  return Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
}

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
};

// ---- BLAKE2b-512 (RFC 7693), for the SS58 checksum only ----

const IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const M64 = (1n << 64n) - 1n;
const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & M64;

export function blake2b512(data) {
  const h = IV.slice();
  h[0] ^= 0x01010040n; // digest length 64, no key
  const blocks = Math.max(1, Math.ceil(data.length / 128));
  for (let b = 0; b < blocks; b++) {
    const chunk = new Uint8Array(128);
    chunk.set(data.subarray(b * 128, b * 128 + 128));
    const m = [];
    for (let i = 0; i < 16; i++) {
      let w = 0n;
      for (let j = 7; j >= 0; j--) w = (w << 8n) | BigInt(chunk[i * 8 + j]);
      m.push(w);
    }
    const last = b === blocks - 1;
    const t = BigInt(last ? data.length : (b + 1) * 128);
    const v = h.concat(IV);
    v[12] ^= t & M64;
    v[13] ^= t >> 64n;
    if (last) v[14] ^= M64;
    const G = (a, b2, c, d, x, y) => {
      v[a] = (v[a] + v[b2] + x) & M64; v[d] = rotr(v[d] ^ v[a], 32n);
      v[c] = (v[c] + v[d]) & M64;      v[b2] = rotr(v[b2] ^ v[c], 24n);
      v[a] = (v[a] + v[b2] + y) & M64; v[d] = rotr(v[d] ^ v[a], 16n);
      v[c] = (v[c] + v[d]) & M64;      v[b2] = rotr(v[b2] ^ v[c], 63n);
    };
    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r % 10];
      G(0, 4, 8, 12, m[s[0]], m[s[1]]);  G(1, 5, 9, 13, m[s[2]], m[s[3]]);
      G(2, 6, 10, 14, m[s[4]], m[s[5]]); G(3, 7, 11, 15, m[s[6]], m[s[7]]);
      G(0, 5, 10, 15, m[s[8]], m[s[9]]); G(1, 6, 11, 12, m[s[10]], m[s[11]]);
      G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 64; i++) out[i] = Number((h[i >> 3] >> BigInt(8 * (i & 7))) & 0xffn);
  return out;
}

// ---- identities ----

export const didKey = (publicKey) => "did:key:z" + base58(concat(Uint8Array.of(0xed, 0x01), publicKey));

export function ss58(publicKey, prefix = 42) {
  if (prefix < 0 || prefix > 63) throw new Error("only simple SS58 prefixes (0-63)");
  const body = concat(Uint8Array.of(prefix), publicKey);
  const sum = blake2b512(concat(enc.encode("SS58PRE"), body)).subarray(0, 2);
  return base58(concat(body, sum));
}

// ---- keys ----

const PKCS8_ED25519 = fromHex("302e020100300506032b657004220420"); // RFC 8410 header before the seed

const b64urlDecode = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

async function wrap(privateKey, publicKeyObj) {
  const jwk = await subtle.exportKey("jwk", privateKey);
  const seed = b64urlDecode(jwk.d);
  const publicKey = new Uint8Array(await subtle.exportKey("raw", publicKeyObj));
  return { seed, publicKey, did: didKey(publicKey), address: ss58(publicKey), privateKey };
}

/** A fresh key. `seed` is the only secret: store it yourself, never send it. */
export async function generate() {
  const kp = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  return wrap(kp.privateKey, kp.publicKey);
}

/** Rebuild a key from a 32-byte seed (Uint8Array or hex). */
export async function fromSeed(seed) {
  const s = typeof seed === "string" ? fromHex(seed) : seed;
  if (s.length !== 32) throw new Error("seed must be 32 bytes");
  const privateKey = await subtle.importKey("pkcs8", concat(PKCS8_ED25519, s), "Ed25519", true, ["sign"]);
  const jwk = await subtle.exportKey("jwk", privateKey);
  const publicKeyObj = await subtle.importKey("raw", b64urlDecode(jwk.x), "Ed25519", true, ["verify"]);
  return wrap(privateKey, publicKeyObj);
}

export async function sign(key, bytes) {
  return new Uint8Array(await subtle.sign("Ed25519", key.privateKey, bytes));
}

// ---- TechnoCore: signed messages ----

export const ROOM_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
export const MAX_TEXT = 4096;

/** The server's single-line sweep (store.py clean_text): sign what will be stored. */
export const sweep = (text) => text.replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu, " ").trim();

/** Sign `<room>|<nonce>|<text>`. The nonce must grow per key and room; a ms clock works. */
export async function signMessage(key, room, text, nonce = Date.now()) {
  if (!ROOM_RE.test(room)) throw new Error("bad room name");
  const clean = sweep(text);
  if (!clean) throw new Error("empty text after the single-line sweep");
  if ([...clean].length > MAX_TEXT) throw new Error(`text over ${MAX_TEXT} characters`);
  const n = String(nonce);
  if (!/^[0-9]{1,19}$/.test(n)) throw new Error("nonce must be 1-19 digits");
  const sig = base64url(await sign(key, enc.encode(`${room}|${n}|${clean}`)));
  return { room, did: key.did, sig, nonce: n, text: clean };
}

/** Post a signed message. Public and irreversible: rooms are world-readable. */
export async function publish(msg, base = "https://technocore.chat") {
  const res = await fetch(`${base}/r/${msg.room}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ did: msg.did, sig: msg.sig, nonce: msg.nonce, text: msg.text }),
  });
  const body = await res.text();
  if (!res.ok) throw new Error(`${res.status} ${body.split("\n")[0]}`);
  return body;
}

// ---- FLOP devnet gateway: wallet enrollment (devnet only) ----
// GET challenge -> sign its exact text -> POST it back for a bearer key scoped to one model.
// The account needs >= 1 devnet FLOP first (https://faucet.flop.network, human verification).

export async function enrollDevnet(key, api = "https://api.flop.network/v1") {
  const q = new URLSearchParams({ address: key.address });
  const ch = await fetch(`${api}/enroll/wallet/challenge?${q}`);
  if (!ch.ok) throw new Error(`challenge: ${ch.status} ${await ch.text()}`);
  const { message } = await ch.json();
  const signature = "0x" + toHex(await sign(key, enc.encode(message)));
  const res = await fetch(`${api}/enroll/wallet`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: key.address, message, signature }),
  });
  if (!res.ok) throw new Error(`enroll: ${res.status} ${await res.text()}`);
  return res.json(); // { key, model, remaining_quota, expires_at }: the bearer is shown once
}
