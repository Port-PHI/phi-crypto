# Changelog

All notable changes to **phi-crypto** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/).

## [0.5.0] - 2026-06-28

The public release of the Phi cryptographic core: one Rust implementation built to three
outputs — a C-ABI staticlib for phi-chain (Go), WebAssembly for the web, and a native
rlib. No hand-rolled cryptography; every primitive is a thin wrapper over a mature, audited
crate, and the build is fully vendored and reproducible offline.

### Added

- **`bbs`** — BBS+ unlinkable selective disclosure over BLS12-381 behind a single
  `CryptoSuite` trait (`DocknetBbsPlus` over `docknetwork/crypto`): deterministic
  parameters, a Fiat-Shamir challenge with Blake2b, and
  `generate_keypair` / `sign_credential` / `derive_proof` / `verify_proof` plus
  `SelectiveProof::{to_bytes,from_bytes}`. Disclosure is bounded at every entry point —
  `message_count` is capped at `MAX_BBS_MESSAGES` (64) and validated in O(1) before any
  parameters are derived — and the length-prefixed decoder uses checked arithmetic so a
  hostile length cannot wrap a bounds check on 32-bit/wasm targets.
- **`bbs_2023`** — the W3C `bbs-2023` interoperability suite, a thin wrapper over the
  audited `pairing_crypto` crate (MATTR/DIF), pinned, for the
  `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_` ciphersuite, behind the same `CryptoSuite`
  trait. Deterministic signing matches the official IETF/W3C vectors byte-for-byte. Native
  targets only (the `blst` C backend does not build for wasm32 without a wasm-capable C
  toolchain); the web path uses `phi-bbs-v1`.
- **`did`** — key generation and ECDSA sign/verify over both curves (secp256k1 and
  secp256r1), with enforced low-S and a zeroized secret. `did_from_public` canonicalizes the
  public key to one SEC1 encoding and derives `did:phi:<64 hex characters>` from the full
  32-byte SHA-256 digest, returning a `Result`. The derivation is fail-closed: bytes that are
  not a valid curve point are rejected up front rather than hashed, and a key supplied
  compressed or uncompressed maps to a single DID.
- **`webauthn`** — a WebAuthn verifier (P-256) over `authenticatorData ‖
  SHA256(clientDataJSON)`: type / challenge / origin / rpIdHash (constant-time) /
  user-presence / low-S, accepting DER or raw signatures.
- **`voting`** — `compute_nullifier` (a length-prefixed hash for anti-double-vote) plus
  threshold tallying over distinct nullifiers.
- **`semaphore`** — binds a BBS eligibility proof to a per-election nullifier and ballot
  choice: `external_nullifier`, `nullifier`, `bind_nonce(election_id, nullifier, signal)`
  (domain `phi-vote-bind-v2`, length-prefixed inputs), and `verify_bound_proof`, exported
  over the C-ABI as `phi_semaphore_verify_vote` (which takes the `signal`, so an accepted
  ballot is non-malleable). A third party cannot replay an eligibility proof under a
  different nullifier or re-tag the chosen option. The binding layer is not Sybil-resistant
  on its own; production vote tallies require the zero-knowledge nullifier-derivation proof,
  a tracked follow-up.
- **`ffi`** — the C-ABI boundary for non-Rust consumers (the only `unsafe` module): a
  panic-free, fail-closed boundary with the generated `phi_crypto.h` header and
  `cbindgen.toml`. Regression tests pin that `phi_bbs2023_verify_proof` and
  `phi_compute_nullifier` reject null/empty input — returning an error rather than panicking
  or reading out of bounds across the boundary — and the `as_slice` safety contract (the
  caller passes the buffer's true length) is documented.
- **`wasm`** — `wasm-bindgen` bindings for the browser (`generateKeypair`, `sign`,
  `verifySignature`, `didFromPublic`, `webauthnVerify`, `computeNullifier`, the full BBS+
  API, and `semaphoreNullifier` / `semaphoreBindNonce`). The wasm dependencies are gated to
  the `wasm32` target, so the native build is unaffected, and the
  `cargo build --target wasm32-unknown-unknown --lib` step is a blocking CI gate.
- **Secret hygiene** — issuer BBS+ and DID secret keys are wrapped in `Zeroizing` /
  `ZeroizeOnDrop` so they are wiped from memory on drop; the WASM key wrappers zeroize their
  secret on drop as well, and the `Vec` handed to JS by the `secret` getter is a caller-owned
  copy.
- **Build profile** — the C-ABI staticlib/cdylib and the WASM module are built release-only,
  so `panic="abort"` governs the FFI boundary, while dev/test keep the default unwind so the
  test harness can catch panics.
- **Offline self-containment** — all dependencies are vendored under `vendor/` (including the
  `docknetwork/crypto` and `pairing_crypto` stacks); `.cargo/config.toml` redirects sources to
  `vendor/`, so build, test, clippy, and the wasm32 build run with no network access.
- **Supply chain** — a `cargo-deny` policy (advisories, no wildcard versions, git sources
  restricted to the pinned cryptography forks), a reproducible-vendor CI job that fails on any
  drift from a fresh `cargo vendor` (git dependencies are not checksummed in `Cargo.lock`),
  a dependency fork watchlist in `SECURITY.md`, and every third-party GitHub Action pinned to
  a full commit SHA with a `.github/dependabot.yml` (scoped to the `github-actions` ecosystem)
  keeping them current.
- **Publishing hygiene** — `LICENSE` (Apache-2.0), `NOTICE`, README, `SECURITY.md`,
  `CONTRIBUTING.md`, `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, the CI workflow, and examples.

---

*Homaan Smart Data Co. — portphi.com*
