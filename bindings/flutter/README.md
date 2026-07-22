<!-- SPDX-License-Identifier: Apache-2.0 -->
# phi-crypto — Flutter FFI binding

The `flutter_rust_bridge` output of [phi-crypto](../../). It lets the Phi mobile app call the real
crypto core natively (on-device signing, WebAuthn assertion verification, BBS+ selective
disclosure, voting nullifiers) instead of reimplementing any of it.

This is a **separate, self-contained crate** — it depends on the core by path and does **not** modify
it, so the core's C-ABI staticlib (hash-pinned by phi-chain) is completely unaffected.

## Layout

```
bindings/flutter/
├── flutter_rust_bridge.yaml   # codegen config (rust_input: crate::api)
├── rust/                      # phi_crypto_flutter — the FFI crate
│   ├── src/api.rs             # thin, safe wrappers mirroring ../../src/wasm.rs (edit this)
│   ├── src/frb_generated.rs   # generated — do not edit
│   ├── src/api_tests.rs       # round-trip + byte-for-byte cross-checks against the core
│   ├── .cargo/config.toml + vendor/   # self-contained offline build
│   └── deny.toml              # supply-chain policy (in lock-step with the core)
└── dart/                      # phi_crypto_ffi — self-contained Dart package
    ├── pubspec.yaml
    └── lib/src/rust/          # generated Dart bindings — do not edit
```

`api.rs` is the only hand-written surface. Every function is a thin wrapper over the core
(`did` / `bbs` / `voting` / `semaphore` / `webauthn`), byte-compatible with the WASM output.

## Build (offline, vendored)

All builds are fully offline against the committed `rust/vendor/` tree. Run from `rust/`:

```bash
# Host (used by unit tests and desktop) → libphi_crypto_flutter.dylib / .so
cargo build --release --locked --offline

# Android (requires the Android NDK + `cargo-ndk`); emits .so per ABI into the Dart package
cargo ndk -t arm64-v8a -t armeabi-v7a -o ../dart/android/src/main/jniLibs \
    build --release --locked --offline

# iOS (requires the aarch64-apple-ios target) → libphi_crypto_flutter.a (staticlib)
cargo build --release --locked --offline --target aarch64-apple-ios
```

## Test / lint (offline)

```bash
cargo fmt --all --check
cargo test   --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo deny check advisories bans sources
```

## Regenerating the bindings

The generated Rust and Dart are committed, so day-to-day builds need no codegen. After editing
`rust/src/api.rs`, regenerate with the **pinned** codegen version (must equal the
`flutter_rust_bridge` crate/Dart versions, currently `2.12.0`) from this directory:

```bash
flutter_rust_bridge_codegen generate      # reads flutter_rust_bridge.yaml
```

Then re-run the test/lint gates above. If dependencies change, refresh the vendor tree with
`cargo vendor` (an online step) and commit the result; CI verifies zero vendor drift.

## Scope

Mirrors the WASM **holder** surface. `bbs-2023` (W3C interop suite) and the live on-chain WebAuthn
verifier are out of scope here, exactly as in `src/wasm.rs`.

### `vote_prove` is deliberately not reachable from Dart

`api::vote_prove` exists behind the `voting_snark` feature and is covered by Rust tests, but it has
**no entry in the generated bridge glue**, so Dart cannot call it. This is intentional, and it is not
a gap to be closed by hand-writing a `cfg`-gated glue entry.

`flutter_rust_bridge` dispatches on a numeric `funcId` assigned by sorting the API surface by name,
and the Dart side compiles that table as constants (`funcId: 13` → `verify_signature`, `funcId: 14` →
`webauthn_verify`). Dart has no equivalent of a Cargo feature, so it cannot have two tables. Adding
`vote_prove` under `#[cfg(feature = "voting_snark")]` would insert it at 14 in a gated build — between
`verify_signature` and `webauthn_verify` — and shift `webauthn_verify` to 15 on the Rust side only.
Dart would keep calling 14 for `webauthn_verify` and land in `vote_prove`, decoding WebAuthn arguments
as vote-proof arguments at the FFI boundary. A silently mis-dispatched verification path is a far
worse outcome than an unexposed prover.

The feature is off until the external cryptographic audit of the derivation proof clears, so nothing
needs this yet. When it is activated, expose it by **regenerating** the bindings (see above) with the
feature enabled and committing both the Rust and Dart sides together, so the two tables stay in step —
never by editing `frb_generated.rs` by hand, which the next codegen run would overwrite anyway.
