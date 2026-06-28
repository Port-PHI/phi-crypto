// SPDX-License-Identifier: Apache-2.0
//! # phi-crypto — Phi network cryptographic core
//!
//! The single implementation point for the network's sensitive cryptography. Written once in Rust
//! and served to three consumers: web (WASM), the Flutter app (FFI), and phi-chain/Go (C-ABI).
//!
//! Non-negotiable principle: no hand-rolled cryptography here — everything is a thin wrapper over
//! audited crates (`k256`/`p256` from RustCrypto, `bbs_plus` from docknetwork). A crypto bug across
//! four parallel implementations is catastrophic, so one core yields three outputs.
//!
//! Modules:
//! - [`bbs`] — unlinkable selective disclosure over BBS+ (behind the single `CryptoSuite` trait).
//! - [`did`] — key generation, sign/verify over k256/p256, `did:phi:...` identifiers.
//! - [`webauthn`] — WebAuthn verifier (P-256); called by phi-chain for a consensus-critical precompile.
//! - [`voting`] — nullifier (anti-double-vote) + threshold tally.
//! - [`semaphore`] — binds a BBS eligibility proof to a per-election nullifier (anti-replay).
//! - [`ffi`] — C-ABI boundary for non-Rust consumers (phi-chain/Go) — the only `unsafe` module.

// No unsafe is allowed in the core; the only exceptions are reviewed boundary modules explicitly
// marked with `#![allow(unsafe_code)]`: `ffi` (hand-written C-ABI unsafe) and `wasm` (only the
// generated wasm-bindgen glue, no hand-written unsafe). `deny` rather than `forbid` so local allows work.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod bbs;
pub mod did;
pub mod error;
pub mod ffi;
pub mod semaphore;
pub mod voting;
pub mod webauthn;

// The WASM output compiles only for the wasm32 target build (native builds are left untouched).
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// W3C bbs-2023 interop suite (audited pairing_crypto / blst). Native targets only: the blst C
// backend does not build for wasm32 without a wasm-capable C toolchain, so wasm keeps phi-bbs-v1.
#[cfg(not(target_arch = "wasm32"))]
pub mod bbs_2023;

pub use error::CryptoError;
