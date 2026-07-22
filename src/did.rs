// SPDX-License-Identifier: Apache-2.0
//! DID operations and dual-curve signing.

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

/// A key pair.
pub struct KeyPair {
    /// Curve.
    pub curve: Curve,
    /// Raw secret key (32 bytes) — sensitive; zeroized after use.
    pub secret: Zeroizing<Vec<u8>>,
    /// Canonical SEC1 public key as emitted by `to_sec1_bytes()` for this curve.
    pub public: Vec<u8>,
}

/// Generates a fresh key pair on the requested curve.
pub fn generate_keypair(curve: Curve) -> KeyPair {
    match curve {
        Curve::Secp256k1 => {
            let sk = k256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
            let pk = k256::ecdsa::VerifyingKey::from(&sk);
            // Wrap the transient scalar bytes so this stack copy is wiped on drop, not just the Vec.
            let sk_bytes = Zeroizing::new(sk.to_bytes());
            KeyPair {
                curve,
                secret: Zeroizing::new(sk_bytes.to_vec()),
                public: pk.to_sec1_bytes().to_vec(),
            }
        }
        Curve::Secp256r1 => {
            let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
            let pk = p256::ecdsa::VerifyingKey::from(&sk);
            // Wrap the transient scalar bytes so this stack copy is wiped on drop, not just the Vec.
            let sk_bytes = Zeroizing::new(sk.to_bytes());
            KeyPair {
                curve,
                secret: Zeroizing::new(sk_bytes.to_vec()),
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

/// Verifies a signature.
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

/// Canonicalize a public key to the curve's canonical SEC1 encoding.
fn canonical_sec1(curve: Curve, public: &[u8]) -> Option<Vec<u8>> {
    match curve {
        Curve::Secp256k1 => Some(
            k256::ecdsa::VerifyingKey::from_sec1_bytes(public)
                .ok()?
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        ),
        Curve::Secp256r1 => Some(
            p256::ecdsa::VerifyingKey::from_sec1_bytes(public)
                .ok()?
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        ),
    }
}

/// DID from a public key: `did:phi:<hex(SHA-256(tag ‖ canonical_sec1(pk)))>` (full 32-byte digest).
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

    /// Fixed non-secret scalar used to make the encoding vectors below reproducible.
    const KAT_SCALAR: [u8; 32] = [0x11; 32];

    /// The canonical SEC1 encoding, pinned byte-for-byte on both curves.
    #[test]
    fn canonical_sec1_encoding_is_pinned() {
        let k1_pub = k256::ecdsa::SigningKey::from_bytes(&KAT_SCALAR.into())
            .unwrap()
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();
        let r1_pub = p256::ecdsa::SigningKey::from_bytes(&KAT_SCALAR.into())
            .unwrap()
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();

        let k1 = canonical_sec1(Curve::Secp256k1, &k1_pub).unwrap();
        assert_eq!(k1.len(), 33, "secp256k1 canonicalizes COMPRESSED");
        assert!(matches!(k1[0], 0x02 | 0x03), "compressed SEC1 prefix");
        assert_eq!(
            hex::encode(&k1),
            "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
        );

        let r1 = canonical_sec1(Curve::Secp256r1, &r1_pub).unwrap();
        assert_eq!(r1.len(), 65, "secp256r1 canonicalizes UNCOMPRESSED");
        assert_eq!(r1[0], 0x04, "uncompressed SEC1 prefix");
        assert_eq!(
            hex::encode(&r1),
            "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4e\
             d194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794"
                .replace(['\\', '\n', ' '], "")
        );
    }

    /// The identifiers derived from those vectors, pinned end to end.
    #[test]
    fn did_derivation_is_pinned() {
        let k1_pub = k256::ecdsa::SigningKey::from_bytes(&KAT_SCALAR.into())
            .unwrap()
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();
        let r1_pub = p256::ecdsa::SigningKey::from_bytes(&KAT_SCALAR.into())
            .unwrap()
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();

        assert_eq!(
            did_from_public(Curve::Secp256k1, &k1_pub).unwrap(),
            "did:phi:2580a99f69c809435c9ba44f68100a2970fa7fa5923d0fd9ca2befc537334244"
        );
        assert_eq!(
            did_from_public(Curve::Secp256r1, &r1_pub).unwrap(),
            "did:phi:1a3d5be062c4389f9a2c4097549d0c7f474a0176238b2f229475bd5842f1663f"
        );
    }

    /// Canonicalization round-trips: the emitted bytes parse back to the same point, and a key handed in EITHER SEC1 form canonicalizes to one encoding and therefore to one identifier.
    #[test]
    fn canonical_sec1_round_trips_and_absorbs_both_input_forms() {
        for curve in [Curve::Secp256k1, Curve::Secp256r1] {
            let kp = generate_keypair(curve);
            let canonical = canonical_sec1(curve, &kp.public).unwrap();

            assert_eq!(
                canonical_sec1(curve, &canonical).unwrap(),
                canonical,
                "canonicalization must be idempotent"
            );

            let (compressed, uncompressed) = match curve {
                Curve::Secp256k1 => {
                    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&kp.public).unwrap();
                    (
                        vk.to_encoded_point(true).as_bytes().to_vec(),
                        vk.to_encoded_point(false).as_bytes().to_vec(),
                    )
                }
                Curve::Secp256r1 => {
                    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&kp.public).unwrap();
                    (
                        vk.to_encoded_point(true).as_bytes().to_vec(),
                        vk.to_encoded_point(false).as_bytes().to_vec(),
                    )
                }
            };
            assert_eq!(compressed.len(), 33);
            assert_eq!(uncompressed.len(), 65);
            assert_eq!(
                did_from_public(curve, &compressed).unwrap(),
                did_from_public(curve, &uncompressed).unwrap(),
                "both SEC1 forms of one key must yield one identifier"
            );
        }
    }

    fn roundtrip(curve: Curve) {
        let kp = generate_keypair(curve);
        let msg = b"phi network test message";
        let sig = sign(curve, &kp.secret, msg).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verify(curve, &kp.public, msg, &sig));
        assert!(!verify(curve, &kp.public, b"tampered", &sig));
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
    }

    #[test]
    fn did_is_canonical_across_sec1_encodings() {
        let kp = generate_keypair(Curve::Secp256r1);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&kp.public).unwrap();
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
