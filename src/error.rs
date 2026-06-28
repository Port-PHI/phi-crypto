// SPDX-License-Identifier: Apache-2.0
//! Unified phi-crypto errors. Mapped to numeric error codes at the FFI boundary (panic = UB).

use core::fmt;

/// A cryptographic operation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid input (wrong length, malformed encoding).
    InvalidInput(&'static str),
    /// Invalid or unparseable key.
    InvalidKey,
    /// Invalid or unparseable signature.
    InvalidSignature,
    /// Verification failed (signature/proof is not valid).
    VerificationFailed,
    /// Unsupported curve.
    UnsupportedCurve,
    /// Internal error from the underlying crate.
    Backend(&'static str),
}

impl CryptoError {
    /// Stable numeric code for the FFI boundary (C-ABI). Zero = success; these values are never 0.
    pub fn code(&self) -> i32 {
        match self {
            CryptoError::InvalidInput(_) => 1,
            CryptoError::InvalidKey => 2,
            CryptoError::InvalidSignature => 3,
            CryptoError::VerificationFailed => 4,
            CryptoError::UnsupportedCurve => 5,
            CryptoError::Backend(_) => 6,
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidInput(s) => write!(f, "invalid input: {s}"),
            CryptoError::InvalidKey => write!(f, "invalid key"),
            CryptoError::InvalidSignature => write!(f, "invalid signature"),
            CryptoError::VerificationFailed => write!(f, "verification failed"),
            CryptoError::UnsupportedCurve => write!(f, "unsupported curve"),
            CryptoError::Backend(s) => write!(f, "backend error: {s}"),
        }
    }
}

impl std::error::Error for CryptoError {}
