<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/phi-mark-dark.svg">
  <img src="assets/phi-mark.svg" alt="Phi (φ)" width="170">
</picture>

# PHI-crypto — the cryptography of PHI identity

[![CI](https://github.com/Port-PHI/phi-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/Port-PHI/phi-crypto/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org/)

**English** · [**فارسی**](./README.fa.md)

Homaan Smart Data Co. · [portphi.com](https://portphi.com)

</div>

---

**The privacy-preserving cryptography behind proof of personhood, authentication, and verifiable credentials** · *never hand-roll crypto*

## What phi-crypto is

**phi-crypto** is the cryptographic core of the [Phi](https://portphi.com) network — the identity
blockchain that lets a person prove who they are, and what they are entitled to claim, **without
exposing their raw personal data.** This library is the engine that makes that possible: the
zero-knowledge proofs, decentralized identifiers, and device-bound authentication that turn a
once-verified human into a private, self-sovereign, verifiable digital identity.

It is written **once in Rust** and serves every Phi consumer from a single implementation: the chain
(Go, via a C-ABI), the mobile app (FFI), and the web (WebAssembly). One core, three outputs — because
a cryptographic bug duplicated across parallel implementations would be a catastrophe, the sensitive
cryptography of the entire network lives in exactly one verifiable place.

The library **never hand-rolls cryptography.** Every primitive is a thin, reviewed wrapper over a
mature, audited crate (`docknetwork/crypto` and `pairing_crypto` for BBS+, RustCrypto's `k256`/`p256`
for signatures, arkworks/blst for BLS12-381). Full attribution is in [`NOTICE`](./NOTICE).

## What it powers

phi-crypto provides the building blocks of Phi's identity layer:

- **Verifiable credentials & selective disclosure (`bbs`, `bbs_2023`).** BBS+ unlinkable
  selective-disclosure signatures over BLS12-381. A holder can prove a statement — *"over 18",
  "resident of city X", "a verified human"* — **without revealing the data behind it**, and two
  presentations of the same credential cannot be correlated. The `bbs-2023` suite matches the
  official IETF/W3C interoperability vectors byte-for-byte.

- **Decentralized identity (`did`).** Key generation and signing on both curves (secp256k1 and
  secp256r1), `did:phi:…` identifiers, and enforced low-S signatures — the cryptographic backbone of
  a person's self-owned Phi identity.

- **Device-bound authentication (`webauthn`).** A WebAuthn verifier (P-256) over
  `authenticatorData ‖ SHA256(clientDataJSON)`, checking type, challenge, origin, relying-party
  identity, User-Presence, and low-S — so "Sign in with Phi" is backed by a real passkey on a real
  device.

- **Private participation (`voting`, `semaphore`).** Nullifier and threshold-tally primitives that
  bind a credential proof to a single, anonymous action — the basis for one-person-one-vote
  participation without revealing identity.

- **The C-ABI boundary (`ffi`).** The only `unsafe` module: a panic-free, fail-safe boundary that
  lets the chain call into the core across the FFI boundary safely. Verification functions return
  `1` for valid and `0` otherwise — they fail closed.

## One core, three outputs

```
                      ┌─────────────────────────────┐
                      │  phi-crypto (Rust core)      │
                      │  bbs · did · webauthn · vote │
                      └──────────────┬──────────────┘
        ┌──────────────────┬─────────┴──────────┬──────────────────┐
   WASM (wasm.rs)     FFI (flutter_bridge)   C-ABI (ffi.rs + cbindgen)
   web app / site      Phi mobile app         phi-chain / Go (cgo)
```

`crate-type = ["cdylib", "staticlib", "rlib"]` enables all three outputs. The Rust core, the C-ABI
output (consumed by phi-chain), and the WebAssembly bindings are implemented and tested; the
remaining bindings are completed across upcoming updates as their consumers are wired.

## Build & test

The repository is fully self-contained and builds **offline**: every dependency is vendored under
`vendor/` and `.cargo/config.toml` redirects sources there, so nothing is downloaded at build time.

```bash
cargo test                                   # unit + integration (offline, from vendor)
cargo clippy --all-targets -- -D warnings    # must be clean
cargo build --release                        # → target/release/libphi_crypto.{a,dylib}
```

### C-ABI output (for phi-chain)

```bash
cargo build --release
cbindgen --config cbindgen.toml --output phi_crypto.h
```

Consume from Go:

```go
// #cgo LDFLAGS: -L./lib -lphi_crypto
// #include "phi_crypto.h"
import "C"
```

All C-ABI verification functions return `1` on success and `0` otherwise (fail-safe); no panic crosses
the boundary.

### WASM output (for the web)

```bash
cargo build --target wasm32-unknown-unknown        # compile-check
wasm-pack build --target web --out-dir pkg-web     # importable web package (requires wasm-pack)
```

```js
import init, { bbsDeriveProof, bbsVerifyProof } from "./pkg-web/phi_crypto.js";
await init();
const proof = bbsDeriveProof(claims, signature, Uint32Array.of(3), nonce); // reveal only "over 18"
const ok = bbsVerifyProof(proof, issuerPublicKey, nonce);
```

Load the WASM with Subresource Integrity (SRI) in production.

## Security principles

- **Never hand-roll cryptography** — every primitive wraps a mature, audited crate.
- `#![deny(unsafe_code)]` everywhere except the single, reviewed `ffi` module.
- Constant-time comparison of secret material with `subtle` — never `==`; secret keys zeroized with
  `zeroize` after use.
- Enforced low-S on signing; verifiers **fail safe** — they reject on any doubt.
- `Cargo.lock` is committed and every crate is pinned; the build is reproducible and offline.

We welcome responsible disclosure — report vulnerabilities privately as described in
[`SECURITY.md`](./SECURITY.md) (**security@portphi.com**), never via a public issue.

## Built on

BBS+ selective disclosure from the **docknetwork/crypto** and **pairing_crypto** families (over
arkworks/blst, BLS12-381), signing and curve hashing from **RustCrypto** (`k256`/`p256`/`sha2`), and
constant-time comparison from **subtle**. Full attribution is in [`NOTICE`](./NOTICE).

## License

[Apache License 2.0](./LICENSE) — © 2026 Homaan Smart Data Co. All rights reserved.

Designed and invented by **A.Mooraeyan**. The Phi protocol and the original source in this repository
are the intellectual property of Homaan Smart Data Co.; all copyright and patent rights are owned and
reserved by the company, which licenses the software for public use, study, and redistribution under
Apache-2.0. See [`NOTICE`](./NOTICE) for the full ownership, patent, and trademark statement.

---

*Homaan Smart Data Co. — [portphi.com](https://portphi.com)*
