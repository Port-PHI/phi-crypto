# phi-crypto — architecture

phi-crypto is the single cryptographic core of the Phi network. It is written once in Rust and
serves three consumers, so that a cryptographic bug cannot exist in several parallel
implementations. **We never hand-roll cryptography** — every primitive is a thin wrapper over a
mature, audited crate.

## Outputs

| Output | Consumer | Crate type |
|---|---|---|
| Rust `rlib` | Rust callers and tests | `rlib` |
| C-ABI (`staticlib`/`cdylib`) | phi-chain (Go / cgo) | `staticlib`, `cdylib` |
| WASM | web app / website | `cdylib` (target `wasm32`) |
| FFI (Flutter) | mobile app — *planned* | `cdylib` via `flutter_rust_bridge` |

## Modules

- `bbs` — **phi-bbs-v1**: BBS+ unlinkable selective disclosure over BLS12-381, behind the
  `CryptoSuite` trait (backed by `docknetwork/crypto`). Available on all targets, including wasm.
- `bbs_2023` — **W3C `bbs-2023`** interop suite (IRTF CFRG BBS, BLS12-381 SHA-256), backed by the
  audited `pairing_crypto` crate. Native targets only (see [`bbs-2023.md`](bbs-2023.md)).
- `did` — dual-curve (secp256k1 / secp256r1) key generation, ECDSA sign/verify (raw `r‖s`, low-S),
  and `did:phi:<…>` derivation.
- `webauthn` — WebAuthn (P-256) assertion verifier over `authenticatorData ‖ SHA256(clientDataJSON)`
  with type / challenge / origin / rpIdHash / User-Presence / low-S checks.
- `voting` — anti-double-vote `compute_nullifier` and distinct-nullifier threshold tally.
- `ffi` — the C-ABI boundary (the only `unsafe` module): no panics cross the boundary; verifiers
  return `1`/`0` fail-safe.
- `wasm` — wasm-bindgen glue (compiled only for `wasm32`).
- `error` — the unified `CryptoError` mapped to stable numeric codes at the FFI boundary.

## The two BBS suites

| | `phi-bbs-v1` (`bbs`) | `bbs-2023` (`bbs_2023`) |
|---|---|---|
| Backend | docknetwork/crypto (arkworks) | pairing_crypto (blst) |
| Standard | project suite | W3C / IRTF, official-vector conformant |
| Targets | all (incl. wasm) | native only |
| Status | legacy / default | standards interop |

Both sit behind the same `CryptoSuite` trait, so callers select a suite without changing the call
shape.

## Build

Builds are fully offline from the committed `vendor/` directory (see the root `README` and
`.cargo/config.toml`). No dependency is downloaded at build time.

## Security posture

No hand-rolled cryptography: every primitive wraps a mature, audited crate. The build is fully
offline, and every dependency is pinned and vendored for a reproducible, verifiable result.
