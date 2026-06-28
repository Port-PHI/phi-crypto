// SPDX-License-Identifier: Apache-2.0
//! Unlinkable selective disclosure over BBS+ signatures.
//!
//! A credential holder can reveal only a subset of claims (e.g. "over 18"
//! without the birth date), and two presentations of the same credential are
//! unlinkable.
//!
//! No hand-rolled cryptography: a thin wrapper over docknetwork's audited
//! `bbs_plus` (BBS+ on BLS12-381, Schnorr-style proof of knowledge of a
//! signature with Fiat-Shamir).
//!
//! The whole sign/prove path sits behind [`CryptoSuite`] so that moving to the
//! final W3C `bbs-2023` suite touches a single point; do not bypass this trait.

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::Blake2b512;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use bbs_plus::prelude::{
    KeypairG2, PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol, PublicKeyG2, SecretKey,
    SignatureG1, SignatureParamsG1,
};
use dock_crypto_utils::signature::MessageOrBlinding;
use schnorr_pok::compute_random_oracle_challenge;
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Domain label for deterministic generation of signature parameters (h_i generators).
const PARAMS_LABEL: &[u8] = b"phi-bbs-v1";

/// Upper bound on the number of credential claims accepted at the verification boundary.
///
/// `params_for` allocates one generator per claim, so an attacker-chosen `message_count` could
/// otherwise force an unbounded allocation (memory-exhaustion DoS), and `message_count = 0` makes
/// the backend reject with a panic (`assert_ne!` in the generator setup). Both are refused in O(1)
/// before any generator is derived. Phi credentials carry only a handful of claims, so 64 is ample.
pub const MAX_BBS_MESSAGES: u32 = 64;

/// Whether a `(message_count, revealed_count)` pair is in range to verify: a non-zero count within
/// [`MAX_BBS_MESSAGES`], revealing no more claims than the credential holds.
fn message_count_in_range(message_count: u32, revealed_count: usize) -> bool {
    message_count != 0
        && message_count <= MAX_BBS_MESSAGES
        && revealed_count <= message_count as usize
}

/// BBS+ key pair (compressed serialized bytes).
pub struct BbsKeyPair {
    /// Secret key (serialized) — sensitive; zeroized on drop (parity with [`crate::did::KeyPair`]).
    pub secret: Zeroizing<Vec<u8>>,
    /// Issuer public key (serialized).
    pub public: Vec<u8>,
}

/// A selective proof together with its revealed claims (so the verifier can reconstruct).
pub struct SelectiveProof {
    /// Total number of credential claims (to reproduce the parameters).
    pub message_count: u32,
    /// Serialized proof.
    pub proof: Vec<u8>,
    /// Revealed claims: (index, claim bytes).
    pub revealed: Vec<(u32, Vec<u8>)>,
}

impl SelectiveProof {
    /// Deterministic length-prefixed byte encoding for crossing the C-ABI/WASM boundary.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.message_count.to_be_bytes());
        out.extend_from_slice(&(self.proof.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.proof);
        out.extend_from_slice(&(self.revealed.len() as u32).to_be_bytes());
        for (idx, claim) in &self.revealed {
            out.extend_from_slice(&idx.to_be_bytes());
            out.extend_from_slice(&(claim.len() as u32).to_be_bytes());
            out.extend_from_slice(claim);
        }
        out
    }

    /// Byte decoding (inverse of [`SelectiveProof::to_bytes`]).
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        let mut r = Reader { b, pos: 0 };
        let message_count = r.u32()?;
        // Reject a degenerate or oversized count up front — before reading the proof, before any
        // allocation. `message_count = 0` would panic the backend; a large value would force an
        // unbounded generator allocation in `params_for`.
        if message_count == 0 || message_count > MAX_BBS_MESSAGES {
            return Err(CryptoError::InvalidInput("message_count out of range"));
        }
        let proof = r.bytes()?;
        let n = r.u32()? as usize;
        // A holder cannot reveal more claims than the credential has; this also bounds the capacity
        // reserved below to `MAX_BBS_MESSAGES`.
        if n > message_count as usize {
            return Err(CryptoError::InvalidInput(
                "revealed count exceeds message_count",
            ));
        }
        let mut revealed = Vec::with_capacity(n);
        for _ in 0..n {
            let idx = r.u32()?;
            let claim = r.bytes()?;
            revealed.push((idx, claim));
        }
        Ok(SelectiveProof {
            message_count,
            proof,
            revealed,
        })
    }
}

/// Small big-endian reader for safe (panic-free) decoding.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}
impl Reader<'_> {
    fn u32(&mut self) -> Result<u32, CryptoError> {
        // `checked_add` so a near-`usize::MAX` position cannot wrap past the bounds check (the
        // additions are unbounded on 32-bit/wasm targets where `pos + 4` could overflow).
        let end = self
            .pos
            .checked_add(4)
            .ok_or(CryptoError::InvalidInput("truncated"))?;
        if end > self.b.len() {
            return Err(CryptoError::InvalidInput("truncated"));
        }
        // The bounds check above guarantees a 4-byte slice, so the conversion is infallible;
        // map the error anyway to keep this decoder panic-free on every path.
        let chunk: [u8; 4] = self.b[self.pos..end]
            .try_into()
            .map_err(|_| CryptoError::InvalidInput("truncated"))?;
        let v = u32::from_be_bytes(chunk);
        self.pos = end;
        Ok(v)
    }
    fn bytes(&mut self) -> Result<Vec<u8>, CryptoError> {
        let len = self.u32()? as usize;
        let end = self
            .pos
            .checked_add(len)
            .ok_or(CryptoError::InvalidInput("truncated"))?;
        if end > self.b.len() {
            return Err(CryptoError::InvalidInput("truncated"));
        }
        let v = self.b[self.pos..end].to_vec();
        self.pos = end;
        Ok(v)
    }
}

/// Verify a serialized proof (for the C-ABI/WASM boundary).
pub fn verify_proof_bytes(proof_bytes: &[u8], public: &[u8], nonce: &[u8]) -> bool {
    match SelectiveProof::from_bytes(proof_bytes) {
        Ok(p) => verify_proof(&p, public, nonce),
        Err(_) => false,
    }
}

/// Selective-disclosure cryptosuite abstraction (the `bbs-2023` suite is pinned behind it).
pub trait CryptoSuite {
    /// Generate an issuer key pair for a credential with `message_count` claims.
    fn generate_keypair(message_count: u32) -> Result<BbsKeyPair, CryptoError>;
    /// Sign a list of claims (each claim is raw bytes).
    fn sign_credential(claims: &[Vec<u8>], secret: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Build a selective proof revealing only the `reveal` indices (with an anti-replay `nonce`).
    fn derive_proof(
        claims: &[Vec<u8>],
        signature: &[u8],
        reveal: &[usize],
        nonce: &[u8],
    ) -> Result<SelectiveProof, CryptoError>;
    /// Verify a selective proof against the issuer public key and `nonce`.
    fn verify_proof(proof: &SelectiveProof, public: &[u8], nonce: &[u8]) -> bool;
}

/// Default implementation: docknetwork BBS+ on BLS12-381.
pub struct DocknetBbsPlus;

// --- helpers ---

/// Maps a claim to a field element (Fr): `Fr = SHA-256(claim) mod r`.
fn claim_to_fr(claim: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(&Sha256::digest(claim))
}

/// Deterministic signature parameters for `count` claims (both sides derive identically).
fn params_for(count: u32) -> SignatureParamsG1<Bls12_381> {
    SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(PARAMS_LABEL, count)
}

fn ser<T: CanonicalSerialize>(t: &T) -> Result<Vec<u8>, CryptoError> {
    let mut b = Vec::new();
    t.serialize_compressed(&mut b)
        .map_err(|_| CryptoError::Backend("bbs serialize"))?;
    Ok(b)
}

fn deser<T: CanonicalDeserialize>(b: &[u8]) -> Result<T, CryptoError> {
    T::deserialize_compressed(b).map_err(|_| CryptoError::InvalidInput("bbs deserialize"))
}

/// Fiat-Shamir challenge from the transcript contribution plus the external nonce.
fn challenge(contribution: &[u8], nonce: &[u8]) -> Fr {
    let mut bytes = Vec::with_capacity(contribution.len() + nonce.len());
    bytes.extend_from_slice(contribution);
    bytes.extend_from_slice(nonce);
    compute_random_oracle_challenge::<Fr, Blake2b512>(&bytes)
}

impl CryptoSuite for DocknetBbsPlus {
    fn generate_keypair(message_count: u32) -> Result<BbsKeyPair, CryptoError> {
        // Bound message_count before params_for: zero makes the backend panic (assert_ne! in the
        // generator setup) and a huge count drives an unbounded generator allocation (OOM/abort). This
        // mirrors the verify-path guard so the keygen/sign/proof entry points cannot be a DoS surface.
        if message_count == 0 || message_count > MAX_BBS_MESSAGES {
            return Err(CryptoError::InvalidInput("message_count out of range"));
        }
        let mut rng = rand::rngs::OsRng;
        let params = params_for(message_count);
        let kp = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &params);
        Ok(BbsKeyPair {
            secret: Zeroizing::new(ser(&kp.secret_key)?),
            public: ser(&kp.public_key)?,
        })
    }

    fn sign_credential(claims: &[Vec<u8>], secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Bound the claim count before params_for: same DoS surface as generate_keypair.
        if claims.is_empty() {
            return Err(CryptoError::InvalidInput("no claims"));
        }
        if claims.len() > MAX_BBS_MESSAGES as usize {
            return Err(CryptoError::InvalidInput("message_count out of range"));
        }
        let mut rng = rand::rngs::OsRng;
        let params = params_for(claims.len() as u32);
        let sk: SecretKey<Fr> = deser(secret)?;
        let messages: Vec<Fr> = claims.iter().map(|c| claim_to_fr(c)).collect();
        let sig = SignatureG1::<Bls12_381>::new(&mut rng, &messages, &sk, &params)
            .map_err(|_| CryptoError::Backend("bbs sign"))?;
        ser(&sig)
    }

    fn derive_proof(
        claims: &[Vec<u8>],
        signature: &[u8],
        reveal: &[usize],
        nonce: &[u8],
    ) -> Result<SelectiveProof, CryptoError> {
        if claims.is_empty() {
            return Err(CryptoError::InvalidInput("no claims"));
        }
        // Bound the claim count before params_for: same DoS surface as generate_keypair.
        if claims.len() > MAX_BBS_MESSAGES as usize {
            return Err(CryptoError::InvalidInput("message_count out of range"));
        }
        let count = claims.len();
        let mut rng = rand::rngs::OsRng;
        let params = params_for(count as u32);
        let sig: SignatureG1<Bls12_381> = deser(signature)?;
        let messages: Vec<Fr> = claims.iter().map(|c| claim_to_fr(c)).collect();

        let reveal_set: BTreeSet<usize> = reveal.iter().copied().collect();
        if reveal_set.iter().any(|&i| i >= count) {
            return Err(CryptoError::InvalidInput("reveal index out of range"));
        }

        // Each message is either revealed or blinded (randomly); this randomness is the source of unlinkability.
        let mbi = messages.iter().enumerate().map(|(i, m)| {
            if reveal_set.contains(&i) {
                MessageOrBlinding::RevealMessage(m)
            } else {
                MessageOrBlinding::BlindMessageRandomly(m)
            }
        });
        let pok = PoKOfSignatureG1Protocol::init(&mut rng, &sig, &params, mbi)
            .map_err(|_| CryptoError::Backend("bbs pok init"))?;

        let mut revealed_msgs: BTreeMap<usize, Fr> = BTreeMap::new();
        for &i in &reveal_set {
            revealed_msgs.insert(i, messages[i]);
        }

        let mut contribution = Vec::new();
        pok.challenge_contribution(&revealed_msgs, &params, &mut contribution)
            .map_err(|_| CryptoError::Backend("bbs challenge"))?;
        let c = challenge(&contribution, nonce);
        let proof = pok
            .gen_proof(&c)
            .map_err(|_| CryptoError::Backend("bbs gen_proof"))?;

        let revealed: Vec<(u32, Vec<u8>)> = reveal_set
            .iter()
            .map(|&i| (i as u32, claims[i].clone()))
            .collect();
        Ok(SelectiveProof {
            message_count: count as u32,
            proof: ser(&proof)?,
            revealed,
        })
    }

    fn verify_proof(proof: &SelectiveProof, public: &[u8], nonce: &[u8]) -> bool {
        // Bound the work before deriving parameters: a degenerate or oversized `message_count`
        // (e.g. from an in-memory proof not built via `from_bytes`) is rejected in O(1), so
        // `params_for` is never asked to allocate an unbounded number of generators (or zero,
        // which panics the backend).
        if !message_count_in_range(proof.message_count, proof.revealed.len()) {
            return false;
        }
        let params = params_for(proof.message_count);
        let Ok(pk) = deser::<PublicKeyG2<Bls12_381>>(public) else {
            return false;
        };
        let Ok(p) = deser::<PoKOfSignatureG1Proof<Bls12_381>>(&proof.proof) else {
            return false;
        };

        let mut revealed_msgs: BTreeMap<usize, Fr> = BTreeMap::new();
        for (i, bytes) in &proof.revealed {
            if *i as usize >= proof.message_count as usize {
                return false;
            }
            revealed_msgs.insert(*i as usize, claim_to_fr(bytes));
        }

        let mut contribution = Vec::new();
        if p.challenge_contribution(&revealed_msgs, &params, &mut contribution)
            .is_err()
        {
            return false;
        }
        let c = challenge(&contribution, nonce);
        // verify takes the parameters by value (pairing preparation); the clone is required.
        p.verify(&revealed_msgs, &c, pk, params.clone()).is_ok()
    }
}

// --- High-level module API (same trait, with the default implementation) ---

/// Generate an issuer key pair.
pub fn generate_keypair(message_count: u32) -> Result<BbsKeyPair, CryptoError> {
    DocknetBbsPlus::generate_keypair(message_count)
}
/// Sign claims.
pub fn sign_credential(claims: &[Vec<u8>], secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
    DocknetBbsPlus::sign_credential(claims, secret)
}
/// Build a selective proof.
pub fn derive_proof(
    claims: &[Vec<u8>],
    signature: &[u8],
    reveal: &[usize],
    nonce: &[u8],
) -> Result<SelectiveProof, CryptoError> {
    DocknetBbsPlus::derive_proof(claims, signature, reveal, nonce)
}
/// Verify a selective proof.
pub fn verify_proof(proof: &SelectiveProof, public: &[u8], nonce: &[u8]) -> bool {
    DocknetBbsPlus::verify_proof(proof, public, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims() -> Vec<Vec<u8>> {
        vec![
            b"name=alice".to_vec(),
            b"birth_year=1990".to_vec(),
            b"city=metropolis".to_vec(),
            b"over_18=true".to_vec(),
        ]
    }

    #[test]
    fn sign_derive_verify_roundtrip() {
        let claims = sample_claims();
        let kp = generate_keypair(claims.len() as u32).unwrap();
        let sig = sign_credential(&claims, &kp.secret).unwrap();
        // Reveal only "over 18" (index 3) — not birth year, not name.
        let proof = derive_proof(&claims, &sig, &[3], b"nonce-1").unwrap();
        assert_eq!(proof.revealed.len(), 1);
        assert_eq!(proof.revealed[0], (3u32, b"over_18=true".to_vec()));
        assert!(verify_proof(&proof, &kp.public, b"nonce-1"));
    }

    #[test]
    fn rejects_wrong_issuer_key() {
        let claims = sample_claims();
        let kp = generate_keypair(claims.len() as u32).unwrap();
        let sig = sign_credential(&claims, &kp.secret).unwrap();
        let proof = derive_proof(&claims, &sig, &[3], b"n").unwrap();
        let other = generate_keypair(claims.len() as u32).unwrap();
        assert!(
            !verify_proof(&proof, &other.public, b"n"),
            "a wrong issuer key must be rejected"
        );
    }

    #[test]
    fn rejects_wrong_nonce() {
        let claims = sample_claims();
        let kp = generate_keypair(claims.len() as u32).unwrap();
        let sig = sign_credential(&claims, &kp.secret).unwrap();
        let proof = derive_proof(&claims, &sig, &[3], b"nonce-A").unwrap();
        assert!(
            !verify_proof(&proof, &kp.public, b"nonce-B"),
            "a wrong nonce must be rejected (anti-replay)"
        );
    }

    #[test]
    fn rejects_tampered_revealed_claim() {
        let claims = sample_claims();
        let kp = generate_keypair(claims.len() as u32).unwrap();
        let sig = sign_credential(&claims, &kp.secret).unwrap();
        let mut proof = derive_proof(&claims, &sig, &[3], b"n").unwrap();
        // Tamper with the revealed claim (over_18=false).
        proof.revealed[0].1 = b"over_18=false".to_vec();
        assert!(
            !verify_proof(&proof, &kp.public, b"n"),
            "a tampered revealed claim must be rejected"
        );
    }

    /// Encode a `SelectiveProof` wire buffer with an arbitrary `message_count` and no proof/claims.
    fn proof_bytes_with_count(message_count: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&message_count.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // proof length
        out.extend_from_slice(&0u32.to_be_bytes()); // revealed count
        out
    }

    #[test]
    fn rejects_degenerate_message_count_in_o1() {
        // message_count = 0 would panic the backend generator setup; a near-u32::MAX value would
        // force an unbounded generator allocation. Both must be refused without reaching params_for.
        for &mc in &[0u32, u32::MAX - 1] {
            assert!(SelectiveProof::from_bytes(&proof_bytes_with_count(mc)).is_err());
            assert!(
                !verify_proof_bytes(&proof_bytes_with_count(mc), b"pk", b"n"),
                "message_count={mc} must verify to false in O(1)"
            );
        }
        // The same bound holds for an in-memory proof that never went through from_bytes.
        let oversized = SelectiveProof {
            message_count: u32::MAX - 1,
            proof: Vec::new(),
            revealed: Vec::new(),
        };
        assert!(!verify_proof(&oversized, b"pk", b"n"));
        let zero = SelectiveProof {
            message_count: 0,
            proof: Vec::new(),
            revealed: Vec::new(),
        };
        assert!(!verify_proof(&zero, b"pk", b"n"));
    }

    #[test]
    fn keygen_sign_proof_reject_degenerate_message_count() {
        // The keygen/sign/proof entry points must reject message_count ∈ {0, huge} before
        // reaching params_for, instead of panicking (assert_ne! on 0) or OOM-allocating ~u32::MAX
        // generators. Previously only the verify path was guarded.
        assert!(
            generate_keypair(0).is_err(),
            "keygen(0) must error, not panic the backend"
        );
        assert!(
            generate_keypair(u32::MAX - 1).is_err(),
            "keygen(huge) must error, not OOM"
        );
        assert!(
            generate_keypair(MAX_BBS_MESSAGES).is_ok(),
            "the boundary count is still accepted"
        );
        assert!(generate_keypair(MAX_BBS_MESSAGES + 1).is_err());

        // sign/derive are bounded on the claim count (one entry over the max), before touching the key/sig.
        let too_many: Vec<Vec<u8>> = (0..=MAX_BBS_MESSAGES as usize)
            .map(|i| format!("c{i}").into_bytes())
            .collect();
        assert!(
            sign_credential(&too_many, b"sk").is_err(),
            "sign over MAX_BBS_MESSAGES claims must error"
        );
        assert!(
            derive_proof(&too_many, b"sig", &[0], b"n").is_err(),
            "derive over MAX_BBS_MESSAGES claims must error"
        );
    }

    #[test]
    fn rejects_more_revealed_than_message_count() {
        // One claim claimed, two revealed entries — inconsistent; reject at decode.
        let mut out = Vec::new();
        out.extend_from_slice(&1u32.to_be_bytes()); // message_count = 1
        out.extend_from_slice(&0u32.to_be_bytes()); // proof length
        out.extend_from_slice(&2u32.to_be_bytes()); // revealed count = 2 (> message_count)
        for (idx, claim) in [(0u32, b"a".as_slice()), (1u32, b"b".as_slice())] {
            out.extend_from_slice(&idx.to_be_bytes());
            out.extend_from_slice(&(claim.len() as u32).to_be_bytes());
            out.extend_from_slice(claim);
        }
        assert!(SelectiveProof::from_bytes(&out).is_err());
    }

    #[test]
    fn unlinkability_two_proofs_differ() {
        let claims = sample_claims();
        let kp = generate_keypair(claims.len() as u32).unwrap();
        let sig = sign_credential(&claims, &kp.secret).unwrap();
        // Two presentations of the same credential with the same disclosure must differ byte-for-byte (per-presentation randomization).
        let p1 = derive_proof(&claims, &sig, &[3], b"n").unwrap();
        let p2 = derive_proof(&claims, &sig, &[3], b"n").unwrap();
        assert_ne!(
            p1.proof, p2.proof,
            "two presentations must not be linkable (identical) — unlinkability"
        );
        // Both are valid.
        assert!(verify_proof(&p1, &kp.public, b"n"));
        assert!(verify_proof(&p2, &kp.public, b"n"));
    }
}
