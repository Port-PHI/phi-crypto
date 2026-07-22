// SPDX-License-Identifier: Apache-2.0
//! W3C `bbs-2023` interoperable selective disclosure (IRTF CFRG BBS over BLS12-381, SHA-256).

use std::collections::BTreeSet;

use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::{
            KeyPair, PublicKey, SecretKey, BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
            BBS_BLS12381G1_SECRET_KEY_LENGTH, BBS_BLS12381G1_SIGNATURE_LENGTH,
        },
        bls12_381_g1_sha_256::{
            proof_gen as cs_proof_gen, proof_verify as cs_proof_verify, sign as cs_sign,
            verify as cs_verify,
        },
    },
    BbsProofGenRequest, BbsProofGenRevealMessageRequest, BbsProofVerifyRequest, BbsSignRequest,
    BbsVerifyRequest,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::bbs::{BbsKeyPair, CryptoSuite, SelectiveProof};
use crate::error::CryptoError;

/// Secret key length in octets (32).
pub const SECRET_KEY_LEN: usize = BBS_BLS12381G1_SECRET_KEY_LENGTH;
/// Public key length in octets (96, a compressed G2 point).
pub const PUBLIC_KEY_LEN: usize = BBS_BLS12381G1_PUBLIC_KEY_LENGTH;
/// Signature length in octets (80, a compressed G1 point plus a scalar).
pub const SIGNATURE_LEN: usize = BBS_BLS12381G1_SIGNATURE_LENGTH;

/// Encode an optional context octet string: an empty slice maps to "absent", which the IRTF ciphersuite treats as the empty octet string.
fn opt(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        None
    } else {
        Some(bytes.to_vec())
    }
}

/// Derive the issuer public key (96-octet compressed G2) from a 32-octet secret key.
fn public_from_secret(secret_key: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], CryptoError> {
    // Wrap the transient secret-key copy so it is wiped on drop before this returns.
    let sk_bytes = Zeroizing::new(secret_key.to_vec());
    let sk = SecretKey::from_vec(&sk_bytes).map_err(|_| CryptoError::InvalidKey)?;
    Ok(PublicKey::from(&sk).to_octets())
}

/// Generate a fresh BBS key pair.
pub fn generate_keypair() -> Result<BbsKeyPair, CryptoError> {
    let mut ikm = [0u8; 32];
    OsRng.fill_bytes(&mut ikm);
    let key_pair = KeyPair::new(ikm.as_ref(), &[]).ok_or(CryptoError::Backend("bbs2023 keygen"))?;
    ikm.zeroize();
    let mut sk = key_pair.secret_key.to_bytes();
    let public = key_pair.public_key.to_octets().to_vec();
    let secret = Zeroizing::new(sk.to_vec());
    sk.zeroize();
    Ok(BbsKeyPair { secret, public })
}

/// Create a BBS signature over `messages`, bound to `header`.
pub fn sign(
    secret_key: &[u8],
    public_key: &[u8],
    header: &[u8],
    messages: &[Vec<u8>],
) -> Result<Vec<u8>, CryptoError> {
    let sk: &[u8; SECRET_KEY_LEN] = secret_key.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let pk: &[u8; PUBLIC_KEY_LEN] = public_key.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let request = BbsSignRequest {
        secret_key: sk,
        public_key: pk,
        header: opt(header),
        messages: Some(messages),
    };
    let signature = cs_sign(&request).map_err(|_| CryptoError::Backend("bbs2023 sign"))?;
    Ok(signature.to_vec())
}

/// Verify a BBS signature over `messages` bound to `header`.
pub fn verify(public_key: &[u8], header: &[u8], messages: &[Vec<u8>], signature: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (
        <&[u8; PUBLIC_KEY_LEN]>::try_from(public_key),
        <&[u8; SIGNATURE_LEN]>::try_from(signature),
    ) else {
        return false;
    };
    cs_verify(&BbsVerifyRequest {
        public_key: pk,
        header: opt(header),
        messages: Some(messages),
        signature: sig,
    })
    .unwrap_or(false)
}

/// Generate an unlinkable selective-disclosure proof revealing only the `reveal` indices, bound to `presentation_header`.
pub fn proof_gen(
    public_key: &[u8],
    signature: &[u8],
    header: &[u8],
    presentation_header: &[u8],
    messages: &[Vec<u8>],
    reveal: &[usize],
) -> Result<Vec<u8>, CryptoError> {
    let pk: &[u8; PUBLIC_KEY_LEN] = public_key.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let sig: &[u8; SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let reveal_set: BTreeSet<usize> = reveal.iter().copied().collect();
    if reveal_set.iter().any(|&i| i >= messages.len()) {
        return Err(CryptoError::InvalidInput("reveal index out of range"));
    }
    let proof_messages: Vec<BbsProofGenRevealMessageRequest<Vec<u8>>> = messages
        .iter()
        .enumerate()
        .map(|(i, m)| BbsProofGenRevealMessageRequest {
            reveal: reveal_set.contains(&i),
            value: m.clone(),
        })
        .collect();
    let request = BbsProofGenRequest {
        public_key: pk,
        header: opt(header),
        messages: Some(&proof_messages),
        signature: sig,
        presentation_header: opt(presentation_header),
        verify_signature: Some(true),
    };
    cs_proof_gen(&request).map_err(|_| CryptoError::Backend("bbs2023 proof_gen"))
}

/// Verify a selective-disclosure proof against `revealed` (index, value) pairs and the `presentation_header`.
pub fn proof_verify(
    public_key: &[u8],
    header: &[u8],
    presentation_header: &[u8],
    proof: &[u8],
    revealed: &[(usize, Vec<u8>)],
) -> bool {
    let Ok(pk) = <&[u8; PUBLIC_KEY_LEN]>::try_from(public_key) else {
        return false;
    };
    let request: BbsProofVerifyRequest<'_, Vec<u8>> = BbsProofVerifyRequest {
        public_key: pk,
        header: opt(header),
        presentation_header: opt(presentation_header),
        proof,
        messages: if revealed.is_empty() {
            None
        } else {
            Some(revealed)
        },
    };
    cs_proof_verify(&request).unwrap_or(false)
}

/// The W3C `bbs-2023` cryptosuite (BLS12-381, SHA-256) behind the project's uniform [`CryptoSuite`] selective-disclosure API.
pub struct Bbs2023Sha256;

impl CryptoSuite for Bbs2023Sha256 {
    fn generate_keypair(_message_count: u32) -> Result<BbsKeyPair, CryptoError> {
        generate_keypair()
    }

    fn sign_credential(claims: &[Vec<u8>], secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if claims.is_empty() {
            return Err(CryptoError::InvalidInput("no claims"));
        }
        let public = public_from_secret(secret)?;
        let signature = sign(secret, &public, &[], claims)?;
        let mut out = Vec::with_capacity(PUBLIC_KEY_LEN + SIGNATURE_LEN);
        out.extend_from_slice(&public);
        out.extend_from_slice(&signature);
        Ok(out)
    }

    fn derive_proof(
        claims: &[Vec<u8>],
        signature: &[u8],
        reveal: &[usize],
        nonce: &[u8],
    ) -> Result<SelectiveProof, CryptoError> {
        if signature.len() != PUBLIC_KEY_LEN + SIGNATURE_LEN {
            return Err(CryptoError::InvalidSignature);
        }
        let (public, sig) = signature.split_at(PUBLIC_KEY_LEN);
        let proof = proof_gen(public, sig, &[], nonce, claims, reveal)?;
        let reveal_set: BTreeSet<usize> = reveal.iter().copied().collect();
        let revealed: Vec<(u32, Vec<u8>)> = reveal_set
            .iter()
            .map(|&i| (i as u32, claims[i].clone()))
            .collect();
        Ok(SelectiveProof {
            message_count: claims.len() as u32,
            proof,
            revealed,
        })
    }

    fn verify_proof(proof: &SelectiveProof, public: &[u8], nonce: &[u8]) -> bool {
        let revealed: Vec<(usize, Vec<u8>)> = proof
            .revealed
            .iter()
            .map(|(i, v)| (*i as usize, v.clone()))
            .collect();
        proof_verify(public, &[], nonce, &proof.proof, &revealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> Vec<Vec<u8>> {
        vec![
            b"did=did:phi:xyz".to_vec(),
            b"birth_year=1990".to_vec(),
            b"over_18=true".to_vec(),
        ]
    }

    #[test]
    fn suite_sign_derive_verify_roundtrip() {
        let kp = Bbs2023Sha256::generate_keypair(3).unwrap();
        let cred = Bbs2023Sha256::sign_credential(&claims(), &kp.secret).unwrap();
        let proof = Bbs2023Sha256::derive_proof(&claims(), &cred, &[2], b"ph-1").unwrap();
        assert_eq!(proof.revealed, vec![(2u32, b"over_18=true".to_vec())]);
        assert!(Bbs2023Sha256::verify_proof(&proof, &kp.public, b"ph-1"));
    }

    #[test]
    fn suite_rejects_wrong_presentation_header() {
        let kp = Bbs2023Sha256::generate_keypair(3).unwrap();
        let cred = Bbs2023Sha256::sign_credential(&claims(), &kp.secret).unwrap();
        let proof = Bbs2023Sha256::derive_proof(&claims(), &cred, &[2], b"ph-A").unwrap();
        assert!(!Bbs2023Sha256::verify_proof(&proof, &kp.public, b"ph-B"));
    }

    #[test]
    fn suite_rejects_wrong_issuer_key() {
        let kp = Bbs2023Sha256::generate_keypair(3).unwrap();
        let other = Bbs2023Sha256::generate_keypair(3).unwrap();
        let cred = Bbs2023Sha256::sign_credential(&claims(), &kp.secret).unwrap();
        let proof = Bbs2023Sha256::derive_proof(&claims(), &cred, &[2], b"ph").unwrap();
        assert!(!Bbs2023Sha256::verify_proof(&proof, &other.public, b"ph"));
    }

    #[test]
    fn two_presentations_are_unlinkable() {
        let kp = Bbs2023Sha256::generate_keypair(3).unwrap();
        let cred = Bbs2023Sha256::sign_credential(&claims(), &kp.secret).unwrap();
        let p1 = Bbs2023Sha256::derive_proof(&claims(), &cred, &[2], b"ph").unwrap();
        let p2 = Bbs2023Sha256::derive_proof(&claims(), &cred, &[2], b"ph").unwrap();
        assert_ne!(
            p1.proof, p2.proof,
            "two presentations must differ (unlinkability)"
        );
        assert!(Bbs2023Sha256::verify_proof(&p1, &kp.public, b"ph"));
        assert!(Bbs2023Sha256::verify_proof(&p2, &kp.public, b"ph"));
    }

    #[test]
    fn raw_sign_verify_roundtrip_with_header() {
        let kp = generate_keypair().unwrap();
        let msgs = claims();
        let header = b"ctx-header";
        let sig = sign(&kp.secret, &kp.public, header, &msgs).unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(verify(&kp.public, header, &msgs, &sig));
        // A different header must not verify.
        assert!(!verify(&kp.public, b"other", &msgs, &sig));
    }
}
