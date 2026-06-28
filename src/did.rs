// SPDX-License-Identifier: Apache-2.0
//! DID operations and dual-curve signing.
//!
//! Supports two curves: `secp256k1` (Cosmos default) and `secp256r1`/P-256
//! (passkey/Secure Enclave). Signatures are ECDSA with enforced low-S
//! (anti-malleability), output as raw 64-byte `r ‖ s` — compatible with phi-chain.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Signing curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// secp256k1 — Cosmos default.
    Secp256k1,
    /// secp256r1 (P-256) — passkey/Secure Enclave and WebAuthn.
    Secp256r1,
}

impl Curve {
    fn tag(self) -> u8 {
        match self {
            Curve::Secp256k1 => 0x01,
            Curve::Secp256r1 => 0x02,
        }
    }
}

/// A key pair. The secret key is zeroized on drop.
pub struct KeyPair {
    /// Curve.
    pub curve: Curve,
    /// Raw secret key (32 bytes) — sensitive; zeroized after use.
    pub secret: Zeroizing<Vec<u8>>,
    /// Uncompressed SEC1 public key (65 bytes), as emitted by `to_sec1_bytes()` for this curve.
    pub public: Vec<u8>,
}

/// Generates a fresh key pair on the requested curve.
pub fn generate_keypair(curve: Curve) -> KeyPair {
    match curve {
        Curve::Secp256k1 => {
            let sk = k256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
            let pk = k256::ecdsa::VerifyingKey::from(&sk);
            KeyPair {
                curve,
                secret: Zeroizing::new(sk.to_bytes().to_vec()),
                public: pk.to_sec1_bytes().to_vec(),
            }
        }
        Curve::Secp256r1 => {
            let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
            let pk = p256::ecdsa::VerifyingKey::from(&sk);
            KeyPair {
                curve,
                secret: Zeroizing::new(sk.to_bytes().to_vec()),
                public: pk.to_sec1_bytes().to_vec(),
            }
        }
    }
}

/// Signs a message (internal SHA-256 hash; raw 64-byte `r ‖ s` with low-S).
pub fn sign(curve: Curve, secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match curve {
        Curve::Secp256k1 => {
            use k256::ecdsa::{signature::Signer, Signature, SigningKey};
            let sk = SigningKey::from_slice(secret).map_err(|_| CryptoError::InvalidKey)?;
            let sig: Signature = sk.sign(msg);
            let sig = sig.normalize_s().unwrap_or(sig); // enforce low-S
            Ok(sig.to_bytes().to_vec())
        }
        Curve::Secp256r1 => {
            use p256::ecdsa::{signature::Signer, Signature, SigningKey};
            let sk = SigningKey::from_slice(secret).map_err(|_| CryptoError::InvalidKey)?;
            let sig: Signature = sk.sign(msg);
            let sig = sig.normalize_s().unwrap_or(sig); // enforce low-S (P-256 does not normalize automatically)
            Ok(sig.to_bytes().to_vec())
        }
    }
}

/// Verifies a signature. high-S is rejected (signature uniqueness for consensus).
pub fn verify(curve: Curve, public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 64 {
        return false;
    }
    match curve {
        Curve::Secp256k1 => {
            use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let Ok(vk) = VerifyingKey::from_sec1_bytes(public) else {
                return false;
            };
            let Ok(signature) = Signature::from_slice(sig) else {
                return false;
            };
            if signature.normalize_s().is_some() {
                return false; // high-S → reject
            }
            vk.verify(msg, &signature).is_ok()
        }
        Curve::Secp256r1 => {
            use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let Ok(vk) = VerifyingKey::from_sec1_bytes(public) else {
                return false;
            };
            let Ok(signature) = Signature::from_slice(sig) else {
                return false;
            };
            if signature.normalize_s().is_some() {
                return false; // high-S → reject
            }
            vk.verify(msg, &signature).is_ok()
        }
    }
}

/// Canonicalize a public key to the curve's canonical SEC1 encoding. The same key may arrive
/// compressed (33 bytes) or uncompressed (65 bytes); both must map to one identifier, so the point
/// is parsed and re-emitted in one fixed form. Returns `None` if the bytes are not a valid point on
/// `curve`; the caller rejects such keys (fail-closed — raw bytes are never hashed into the
/// identifier namespace).
fn canonical_sec1(curve: Curve, public: &[u8]) -> Option<Vec<u8>> {
    match curve {
        Curve::Secp256k1 => Some(
            k256::ecdsa::VerifyingKey::from_sec1_bytes(public)
                .ok()?
                .to_sec1_bytes()
                .to_vec(),
        ),
        Curve::Secp256r1 => Some(
            p256::ecdsa::VerifyingKey::from_sec1_bytes(public)
                .ok()?
                .to_sec1_bytes()
                .to_vec(),
        ),
    }
}

/// DID from a public key: `did:phi:<hex(SHA-256(tag ‖ canonical_sec1(pk)))>` (full 32-byte digest).
/// The key is canonicalized to one SEC1 encoding first, so the same key supplied compressed or
/// uncompressed yields one DID; hashing the key avoids exposing it in the identifier. An invalid key
/// is rejected: raw, unparsed bytes are never hashed into the identifier namespace, and
/// the full 32-byte digest is used (collision resistance ~2^128, vs ~2^80 for the former 20-byte cut).
pub fn did_from_public(curve: Curve, public: &[u8]) -> Result<String, CryptoError> {
    let canonical = canonical_sec1(curve, public).ok_or(CryptoError::InvalidKey)?;
    let mut h = Sha256::new();
    h.update([curve.tag()]);
    h.update(&canonical);
    let digest = h.finalize();
    Ok(format!("did:phi:{}", hex::encode(digest)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(curve: Curve) {
        let kp = generate_keypair(curve);
        let msg = b"phi network test message";
        let sig = sign(curve, &kp.secret, msg).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verify(curve, &kp.public, msg, &sig));
        // Tampered message → reject.
        assert!(!verify(curve, &kp.public, b"tampered", &sig));
        // Wrong key → reject.
        let other = generate_keypair(curve);
        assert!(!verify(curve, &other.public, msg, &sig));
    }

    #[test]
    fn sign_verify_secp256k1() {
        roundtrip(Curve::Secp256k1);
    }

    #[test]
    fn sign_verify_secp256r1() {
        roundtrip(Curve::Secp256r1);
    }

    #[test]
    fn did_is_stable() {
        let kp = generate_keypair(Curve::Secp256r1);
        let did1 = did_from_public(Curve::Secp256r1, &kp.public).unwrap();
        let did2 = did_from_public(Curve::Secp256r1, &kp.public).unwrap();
        assert_eq!(did1, did2, "the DID must be deterministic");
        assert!(did1.starts_with("did:phi:"));
        // The curve tag is mixed into the digest (h.update([curve.tag()])), so a byte string valid on
        // both curves would still yield distinct DIDs. Post-fail-closed no single key is guaranteed
        // valid on both curves, so that property is enforced in code rather than exercised with one key.
    }

    #[test]
    fn did_is_canonical_across_sec1_encodings() {
        let kp = generate_keypair(Curve::Secp256r1);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&kp.public).unwrap();
        // The same key in both SEC1 encodings: compressed (33 bytes) and uncompressed (65 bytes).
        let compressed = vk.to_encoded_point(true).as_bytes().to_vec();
        let uncompressed = vk.to_encoded_point(false).as_bytes().to_vec();
        assert_eq!(compressed.len(), 33);
        assert_eq!(uncompressed.len(), 65);
        assert_ne!(compressed, uncompressed);
        // Both encodings must canonicalize to one DID.
        let from_compressed = did_from_public(Curve::Secp256r1, &compressed).unwrap();
        let from_uncompressed = did_from_public(Curve::Secp256r1, &uncompressed).unwrap();
        assert_eq!(
            from_compressed, from_uncompressed,
            "the DID must not depend on the SEC1 encoding of the key",
        );
        assert_eq!(
            from_compressed,
            did_from_public(Curve::Secp256r1, &kp.public).unwrap()
        );
    }

    #[test]
    fn rejects_wrong_length_signature() {
        let kp = generate_keypair(Curve::Secp256k1);
        assert!(!verify(Curve::Secp256k1, &kp.public, b"x", &[0u8; 10]));
    }

    #[test]
    fn did_rejects_invalid_key() {
        // Fail-closed: an invalid curve point must never be hashed into the identifier
        // namespace. 0x02 ‖ 32×0xFF has x ≥ the field modulus, so it is not a valid compressed point.
        let mut pk = [0xFFu8; 33];
        pk[0] = 0x02;
        assert!(matches!(
            did_from_public(Curve::Secp256r1, &pk),
            Err(CryptoError::InvalidKey)
        ));
        assert!(matches!(
            did_from_public(Curve::Secp256k1, &pk),
            Err(CryptoError::InvalidKey)
        ));
        // A wrong-length blob is rejected too (never a fabricated id).
        assert!(did_from_public(Curve::Secp256r1, &[0u8; 10]).is_err());
    }

    #[test]
    fn did_valid_key_is_ok_and_full_length() {
        // A valid key yields a 32-byte (64 hex) digest after the H-4 widening.
        let kp = generate_keypair(Curve::Secp256r1);
        let did = did_from_public(Curve::Secp256r1, &kp.public).expect("valid key");
        assert_eq!(
            did.len(),
            "did:phi:".len() + 64,
            "DID must encode a full 32-byte digest"
        );
    }

    #[test]
    fn did_from_public_never_panics_on_arbitrary_bytes() {
        // Deterministic robustness sweep (std-only) standing in for a cargo-fuzz target until the
        // fuzz harness is vendored: many varied byte strings must never panic the derivation, and any
        // accepted identifier must be well-formed (fail-closed, no fabricated ids).
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rng = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..5000 {
            let len = (rng() % 70) as usize; // spans the 33/65-byte valid lengths and many others
            let buf: Vec<u8> = (0..len).map(|_| (rng() & 0xff) as u8).collect();
            for curve in [Curve::Secp256k1, Curve::Secp256r1] {
                match did_from_public(curve, &buf) {
                    Ok(did) => {
                        assert!(did.starts_with("did:phi:"));
                        assert_eq!(did.len(), "did:phi:".len() + 64);
                    }
                    Err(CryptoError::InvalidKey) => {}
                    Err(other) => panic!("unexpected error variant: {other:?}"),
                }
            }
        }
    }
}
