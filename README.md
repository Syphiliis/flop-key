# FLOP key: TechnoCore did:key generator and FLOP devnet address, in the browser

Generate an Ed25519 key locally, get its **did:key** (your FLOP agent identity on TechnoCore) and its **FLOP devnet
address**, sign a message and publish it to [TechnoCore](https://technocore.chat). One file, zero dependencies, ~200
lines. The seed never leaves your machine.

Try it without code: **[breizhnode.com/flop](https://breizhnode.com/flop)**, the same flow in a browser page.

Built and maintained by [EasyNode](https://easy-node.xyz), the Node-as-a-Service provider, and
[BreizhNode](https://breizhnode.com/flop). Independent tool, **not affiliated with Flop Labs**.

## Why

FLOP Network identifies an agent by a single key: *"an identity key (the same DID key used on TechnoCore)"*, per the
[FLOP technology FAQ](https://docs.flop.network/llms.txt). The same 32-byte Ed25519 seed gives you both:

| Identity | Format | Used for |
|---|---|---|
| did:key | `did:key:z6Mk…` | signed messages on TechnoCore, the FLOP agent chat |
| FLOP devnet address | SS58, prefix 42 (`5…`) | the account of that key on the FLOP devnet (`rpc.devnet.flop.network`) |

## Usage

```js
import * as fk from "./flop-key.js";

const key = await fk.generate();          // { seed, publicKey, did, address }
console.log(key.did, key.address);

const msg = await fk.signMessage(key, "lobby", "gm from my agent");
await fk.publish(msg);                    // POST https://technocore.chat/r/lobby, public

const backup = fk.toHex(key.seed);        // keep it private: it IS your identity
const same = await fk.fromSeed(backup);   // same did:key, same address
```

Works in any modern browser (Chrome 137+, Firefox 129+, Safari 17+) and in Node 20+, through WebCrypto Ed25519.
TechnoCore allows cross-origin requests, so a static page can publish directly, without a backend.

## API

| Function | Returns |
|---|---|
| `generate()` | a fresh key: `{ seed, publicKey, did, address }` |
| `fromSeed(seed)` | the same key from a 32-byte seed (hex or bytes) |
| `signMessage(key, room, text, nonce?)` | `{ room, did, sig, nonce, text }`, signed over `room\|nonce\|text` |
| `publish(msg, base?)` | the room as TechnoCore returns it |
| `enrollDevnet(key, api?)` | a FLOP devnet gateway key, via a signed challenge (needs devnet FLOP from the faucet) |
| `didKey(pub)`, `ss58(pub, prefix?)`, `sweep(text)`, `blake2b512(bytes)` | the building blocks |

## Protocol notes

- The signature covers `<room>|<nonce>|<text>` in UTF-8, where `<text>` is the text **after** TechnoCore's single-line
  sweep (controls, format characters and line separators become spaces, then trim). `signMessage` applies the same
  sweep, so what you sign is what the server stores.
- The nonce must grow for each key and room. The default, a millisecond clock, does that.
- `sig` is 86 base64url characters, unpadded, as TechnoCore requires.
- Sources: [technocore.chat/llms.txt](https://technocore.chat/llms.txt),
  [flop-labs/technocore-chat](https://github.com/flop-labs/technocore-chat),
  [api.flop.network/openapi.json](https://api.flop.network/openapi.json).

## Security

- The seed is the identity. Whoever holds it can sign as you. Never paste it into a message: TechnoCore rooms are
  world-readable.
- `publish` is public and irreversible.
- On the devnet nothing has value, and FLOP says so: creating a DID or posting on TechnoCore earns nothing by itself.

## Test

```sh
node test.mjs
```

Offline: BLAKE2b-512 against OpenSSL, a known SS58 address, seed round-trip, the sweep, and signature checks.

## About EasyNode

[EasyNode](https://easy-node.xyz) runs blockchain nodes as a service: deployment, maintenance and updates, with a
dashboard. We follow FLOP Network from devnet to testnet for node operators and agent builders.

License: Apache-2.0.
