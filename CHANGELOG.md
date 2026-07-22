# Changelog

All notable changes to **phi-crypto** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/).

## [1.0.0] — Initial public release

The first public release of the Phi cryptographic core: one Rust implementation compiled to
every consumer output — a C-ABI staticlib for phi-chain (Go), WebAssembly for the web, and a
Flutter FFI binding for the mobile app. No cryptography is hand-rolled; every primitive is a thin,
reviewed wrapper over a mature, externally-audited crate, and the build is fully vendored and
reproducible offline.

### Cryptographic modules

- **`bbs`** (`phi-bbs-v1`) — BBS+ unlinkable selective disclosure over BLS12-381 behind a single
  `CryptoSuite` trait (over `docknetwork/crypto`): deterministic parameters, a Blake2b
  Fiat-Shamir challenge, and sign / derive-proof / verify with a byte-serializable proof.
  Disclosure is bounded — the message count is capped and validated before any parameters are
  derived — and the length-prefixed decoder uses checked arithmetic. Available on every target,
  including wasm.
- **`bbs_2023`** — the W3C `bbs-2023` interoperability suite, a thin wrapper over the audited
  `pairing_crypto` crate (MATTR/DIF) for the `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_`
  ciphersuite behind the same `CryptoSuite` trait. Deterministic signing matches the official
  IETF/W3C vectors byte-for-byte. Native targets only.
- **`did`** — key generation and ECDSA sign/verify over both curves (secp256k1 and secp256r1)
  with enforced low-S and zeroized secrets. `did_from_public` canonicalizes the public key to one
  SEC1 encoding and derives `did:phi:<64 hex>` from the full 32-byte SHA-256 digest, fail-closed:
  bytes that are not a valid curve point are rejected rather than hashed.
- **`webauthn`** — a WebAuthn verifier (P-256) over `authenticatorData ‖ SHA256(clientDataJSON)`
  checking type, challenge, origin, rpIdHash (constant-time), user-presence, and low-S, accepting
  DER or raw signatures.
- **`voting`** and **`semaphore`** — a length-prefixed anti-double-vote `compute_nullifier` and
  distinct-nullifier threshold tally, and a binding layer that ties a BBS eligibility proof to a
  per-election nullifier and ballot choice (exported over the C-ABI as `phi_semaphore_verify_vote`,
  which takes the signal, so an accepted ballot is non-malleable). The binding layer is not
  Sybil-resistant on its own; production tallies require the zero-knowledge nullifier-derivation
  proof.

### Consumer outputs

- **`ffi`** — the C-ABI boundary for non-Rust consumers (the only `unsafe` module): a panic-free,
  fail-closed boundary with a generated `phi_crypto.h` header, and regression tests that pin
  null/empty input to a safe error rather than a panic or an out-of-bounds read across the
  boundary.
- **`wasm`** — `wasm-bindgen` bindings for the browser (signing, DID, WebAuthn, the full BBS+ API,
  and the Semaphore helpers), with wasm dependencies gated to the `wasm32` target so the native
  build is unaffected and the wasm32 build kept as a blocking CI gate.
- **Flutter FFI binding** — a separate, self-contained crate under `bindings/flutter/` that
  exposes the core's holder-side surface to the mobile app natively, byte-compatible with the web
  output. It depends on the core by path and does not modify it, so the C-ABI staticlib is
  byte-for-byte unchanged; the generated Rust and Dart bindings are committed for offline builds.
- **Client-side anonymous-vote prover** — the derivation prover is reachable from both the web and
  the mobile clients, gated end to end behind the `voting_snark` cargo feature so the default WASM
  module and Flutter build are unchanged. Secret material is held in `Zeroizing`, never leaves the
  call, and is never logged.

### Security posture

- **Secret hygiene** — issuer BBS+ and DID secret keys are wrapped so they are wiped from memory
  on drop; secret comparisons are constant-time (`subtle`), and signing enforces low-S.
- **Fail-safe boundary** — release builds set `panic = "abort"`, and no panic crosses the C-ABI
  boundary; verifiers return a safe negative on any error or malformed input.
- **Offline, reproducible supply chain** — all dependencies are vendored, `Cargo.lock` is
  committed and fully pinned, a `cargo-deny` policy restricts advisories and sources, a CI job
  fails on any drift from a fresh vendor, and every third-party GitHub Action is pinned to a full
  commit SHA.
- **Published test vectors** — known-answer vectors for the standards-conformant suite are
  published alongside the code so anyone can independently verify byte-for-byte interoperability.

---

*Homaan Smart Data Co. — portphi.com*
