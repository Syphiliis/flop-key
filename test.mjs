// node tools/flop-key/test.mjs — offline: nothing is sent.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import * as fk from "./flop-key.js";

const ok = (name) => console.log("ok", name);

// BLAKE2b-512 against Node's OpenSSL, across block boundaries.
for (const n of [0, 1, 39, 127, 128, 129, 256, 1000]) {
  const d = randomBytes(n);
  assert.equal(fk.toHex(fk.blake2b512(new Uint8Array(d))), createHash("blake2b512").update(d).digest("hex"));
}
ok("blake2b512 = OpenSSL");

// SS58: the well-known Substrate dev account "Alice", prefix 42 (public key in groups of 16 hex, rule 1).
const alice = fk.fromHex(["d43593c715fdd31c", "61141abd04a99fd6", "822c8558854ccde3", "9a5684e7a56da27d"].join(""));
assert.equal(fk.ss58(alice), "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY");
ok("ss58 prefix 42");

// Key round-trip: a seed rebuilds the same identities.
const key = await fk.generate();
assert.equal(key.seed.length, 32);
assert.match(key.did, /^did:key:z6Mk/);
const again = await fk.fromSeed(fk.toHex(key.seed));
assert.equal(again.did, key.did);
assert.equal(again.address, key.address);
ok("generate / fromSeed");

// Sweep matches store.py clean_text on the cases the manual names.
assert.equal(fk.sweep(" a\nb​c d‮ "), "a b c d");
await assert.rejects(fk.signMessage(key, "lobby", "​\n"), /empty/);
ok("sweep");

// Signed message: canonical 86-char base64url, verifies over room|nonce|text.
const msg = await fk.signMessage(key, "lobby", "gm\nfrom flop-key", 1730000000000);
assert.match(msg.sig, /^[A-Za-z0-9_-]{85}[AQgw]$/);
assert.equal(msg.text, "gm from flop-key");
const pub = await crypto.subtle.importKey("raw", key.publicKey, "Ed25519", false, ["verify"]);
const sigBytes = Uint8Array.from(Buffer.from(msg.sig, "base64url"));
assert.ok(await crypto.subtle.verify("Ed25519", pub, sigBytes, new TextEncoder().encode("lobby|1730000000000|gm from flop-key")));
assert.ok(!(await crypto.subtle.verify("Ed25519", pub, sigBytes, new TextEncoder().encode("lobby|1730000000001|gm from flop-key"))));
await assert.rejects(fk.signMessage(key, "Lobby", "x"), /room/);
ok("signMessage");

console.log(JSON.stringify({ did: msg.did, sig: msg.sig, nonce: msg.nonce, text: msg.text, room: msg.room }));
