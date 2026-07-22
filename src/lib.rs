// SPDX-License-Identifier: Apache-2.0
//! # phi-crypto — Phi network cryptographic core The single implementation point for the network's sensitive cryptography.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod bbs;
pub mod did;
pub mod error;
pub mod ffi;
pub mod secret;
pub mod seed;
pub mod semaphore;
pub mod voting;
pub mod webauthn;

#[cfg(feature = "voting_snark")]
pub mod voting_snark;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(not(target_arch = "wasm32"))]
pub mod bbs_2023;

pub use error::CryptoError;
