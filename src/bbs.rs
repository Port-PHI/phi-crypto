// SPDX-License-Identifier: Apache-2.0
//! Unlinkable selective disclosure over BBS+ signatures.

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::Blake2b512;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

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

/// Domain-separation label for this suite's Fiat-Shamir proof challenge.
const PROOF_CHALLENGE_DOMAIN: &[u8] = b"phi-bbs-proof-v1";

/// Counts how many times the generators were actually derived, per claim count, so the tests can prove the cache is doing its job.
#[cfg(test)]
static DERIVATIONS: Mutex<BTreeMap<u32, u64>> = Mutex::new(BTreeMap::new());

/// How many times `count`'s generators have been derived from scratch.
#[cfg(test)]
fn derivations_for(count: u32) -> u64 {
    DERIVATIONS
        .lock()
        .map(|d| d.get(&count).copied().unwrap_or(0))
        .unwrap_or(0)
}

/// Upper bound on the number of credential claims accepted at the verification boundary.
pub const MAX_BBS_MESSAGES: u32 = 64;

/// Whether a `(message_count, revealed_count)` pair is in range to verify: a non-zero count within [`MAX_BBS_MESSAGES`], revealing no more claims than the credential holds.
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
        if message_count == 0 || message_count > MAX_BBS_MESSAGES {
            return Err(CryptoError::InvalidInput("message_count out of range"));
        }
        let proof = r.bytes()?;
        let n = r.u32()? as usize;
        if n > message_count as usize {
            return Err(CryptoError::InvalidInput(
                "revealed count exceeds message_count",
            ));
        }
        let mut revealed = Vec::with_capacity(n);
        let mut prev: Option<u32> = None;
        for _ in 0..n {
            let idx = r.u32()?;
            if idx >= message_count {
                return Err(CryptoError::InvalidInput("revealed index out of range"));
            }
            if let Some(p) = prev {
                if idx <= p {
                    return Err(CryptoError::InvalidInput(
                        "revealed indices must be strictly increasing",
                    ));
                }
            }
            prev = Some(idx);
            let claim = r.bytes()?;
            revealed.push((idx, claim));
        }
        if r.pos != b.len() {
            return Err(CryptoError::InvalidInput("trailing bytes"));
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
        let end = self
            .pos
            .checked_add(4)
            .ok_or(CryptoError::InvalidInput("truncated"))?;
        if end > self.b.len() {
            return Err(CryptoError::InvalidInput("truncated"));
        }
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

/// Maps a claim to a field element (Fr): `Fr = SHA-256(claim) mod r`.
pub(crate) fn claim_to_fr(claim: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(&Sha256::digest(claim))
}

/// Derives the signature parameters from scratch: one hash-to-curve per claim, plus `g1`/`g2`/`h_0`.
fn derive_params(count: u32) -> SignatureParamsG1<Bls12_381> {
    #[cfg(test)]
    if let Ok(mut d) = DERIVATIONS.lock() {
        *d.entry(count).or_insert(0) += 1;
    }
    SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(PARAMS_LABEL, count)
}

/// Memoized parameters, keyed by claim count.
fn params_cache() -> &'static Mutex<BTreeMap<u32, SignatureParamsG1<Bls12_381>>> {
    static CACHE: OnceLock<Mutex<BTreeMap<u32, SignatureParamsG1<Bls12_381>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Deterministic signature parameters for `count` claims (both sides derive identically).
pub(crate) fn params_for(count: u32) -> SignatureParamsG1<Bls12_381> {
    if count > MAX_BBS_MESSAGES {
        return derive_params(count);
    }
    if let Ok(cache) = params_cache().lock() {
        if let Some(cached) = cache.get(&count) {
            return cached.clone();
        }
    }
    let params = derive_params(count);
    if let Ok(mut cache) = params_cache().lock() {
        cache.insert(count, params.clone());
    }
    params
}

/// Compressed canonical serialization (shared with `voting_snark`).
pub(crate) fn ser<T: CanonicalSerialize>(t: &T) -> Result<Vec<u8>, CryptoError> {
    let mut b = Vec::new();
    t.serialize_compressed(&mut b)
        .map_err(|_| CryptoError::Backend("bbs serialize"))?;
    Ok(b)
}

/// Compressed canonical deserialization with subgroup validation (shared with `voting_snark`).
pub(crate) fn deser<T: CanonicalDeserialize>(b: &[u8]) -> Result<T, CryptoError> {
    let mut cursor = b;
    let v = T::deserialize_compressed(&mut cursor)
        .map_err(|_| CryptoError::InvalidInput("bbs deserialize"))?;
    if !cursor.is_empty() {
        return Err(CryptoError::InvalidInput("bbs deserialize: trailing bytes"));
    }
    Ok(v)
}

/// Assemble the Fiat-Shamir transcript for a `phi-bbs-v1` selective-disclosure proof.
fn proof_transcript(contribution: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut t =
        Vec::with_capacity(PROOF_CHALLENGE_DOMAIN.len() + contribution.len() + nonce.len() + 12);
    put_bytes(&mut t, PROOF_CHALLENGE_DOMAIN);
    put_bytes(&mut t, contribution);
    put_bytes(&mut t, nonce);
    t
}

/// Append a length-prefixed byte string (`u32` big-endian length).
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// Fiat-Shamir challenge over the canonical transcript ([`proof_transcript`]).
fn challenge(contribution: &[u8], nonce: &[u8]) -> Fr {
    compute_random_oracle_challenge::<Fr, Blake2b512>(&proof_transcript(contribution, nonce))
}

impl CryptoSuite for DocknetBbsPlus {
    fn generate_keypair(message_count: u32) -> Result<BbsKeyPair, CryptoError> {
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
        if claims.is_empty() {
            return Err(CryptoError::InvalidInput("no claims"));
        }
        if claims.len() > MAX_BBS_MESSAGES as usize {
            return Err(CryptoError::InvalidInput("message_count out of range"));
        }
        let mut rng = rand::rngs::OsRng;
        let params = params_for(claims.len() as u32);
        let sk: SecretKey<Fr> = deser(secret)?;
        let messages: Zeroizing<Vec<Fr>> =
            Zeroizing::new(claims.iter().map(|c| claim_to_fr(c)).collect());
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
        if claims.len() > MAX_BBS_MESSAGES as usize {
            return Err(CryptoError::InvalidInput("message_count out of range"));
        }
        let count = claims.len();
        let mut rng = rand::rngs::OsRng;
        let params = params_for(count as u32);
        let sig: SignatureG1<Bls12_381> = deser(signature)?;
        let messages: Zeroizing<Vec<Fr>> =
            Zeroizing::new(claims.iter().map(|c| claim_to_fr(c)).collect());

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
            if revealed_msgs
                .insert(*i as usize, claim_to_fr(bytes))
                .is_some()
            {
                return false; // duplicate index
            }
        }
        debug_assert_eq!(revealed_msgs.len(), proof.revealed.len());

        let mut contribution = Vec::new();
        if p.challenge_contribution(&revealed_msgs, &params, &mut contribution)
            .is_err()
        {
            return false;
        }
        let c = challenge(&contribution, nonce);
        p.verify(&revealed_msgs, &c, pk, params.clone()).is_ok()
    }
}

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

    /// Claim counts reserved for the cache tests.
    const CACHE_TEST_COUNT: u32 = 61;
    const CACHE_EQ_COUNT: u32 = 62;

    /// Memoization must be invisible in the result: the cached generators are the same value the old uncached code path produced.
    #[test]
    fn memoized_params_equal_a_fresh_derivation() {
        let fresh = derive_params(CACHE_EQ_COUNT);
        let memoized = params_for(CACHE_EQ_COUNT);
        assert_eq!(
            memoized, fresh,
            "cached generators must equal the direct derivation"
        );
        assert_eq!(ser(&memoized).unwrap(), ser(&fresh).unwrap());
    }

    /// The point of the cache: a second verify at the same claim count does not re-run hash-to-curve.
    #[test]
    fn repeated_params_for_does_not_recompute() {
        let first = params_for(CACHE_TEST_COUNT);
        let after_first = derivations_for(CACHE_TEST_COUNT);
        assert_eq!(
            after_first, 1,
            "the first call derives exactly once and caches it"
        );

        for _ in 0..8 {
            let again = params_for(CACHE_TEST_COUNT);
            assert_eq!(again, first, "every cache hit returns the same generators");
        }
        assert_eq!(
            derivations_for(CACHE_TEST_COUNT),
            after_first,
            "cache hits must not derive again"
        );
    }

    /// A count above the bound is still served correctly, just never cached — so an out-of-range count cannot grow the map.
    #[test]
    fn out_of_range_counts_are_not_cached() {
        let over = MAX_BBS_MESSAGES + 1;
        let _ = params_for(over);
        let _ = params_for(over);
        assert_eq!(
            derivations_for(over),
            2,
            "an out-of-range count derives every time instead of being cached"
        );
        assert!(
            params_cache()
                .lock()
                .map(|c| !c.contains_key(&over))
                .unwrap_or(false),
            "an out-of-range count must never enter the cache"
        );
    }

    /// KNOWN-ANSWER VECTOR for this suite's Fiat-Shamir transcript framing.
    #[test]
    fn proof_transcript_framing_kat() {
        let t = proof_transcript(b"CONTRIBUTION", b"NONCE");
        assert_eq!(
            hex::encode(&t),
            concat!(
                "00000010",                         // len("phi-bbs-proof-v1") = 16
                "7068692d6262732d70726f6f662d7631", // "phi-bbs-proof-v1"
                "0000000c",                         // len("CONTRIBUTION") = 12
                "434f4e545249425554494f4e",         // "CONTRIBUTION"
                "00000005",                         // len("NONCE") = 5
                "4e4f4e4345",                       // "NONCE"
            ),
            "the phi-bbs-v1 proof transcript framing is pinned"
        );
        assert_eq!(
            hex::encode(ser(&challenge(b"CONTRIBUTION", b"NONCE")).unwrap()),
            "e4fac975a93ed8a075f814e320e4146c8284dde6a515c1fca2b5cc54b6a8681f",
            "the derived challenge scalar is pinned"
        );
    }

    /// The domain label is really in the transcript: a proof challenge computed under a different label is a different scalar, so this hash input cannot collide with any other the library computes.
    #[test]
    fn transcript_is_domain_separated() {
        let with_domain = proof_transcript(b"CONTRIBUTION", b"NONCE");
        // The same fields without the leading domain field.
        let mut without_domain = Vec::new();
        put_bytes(&mut without_domain, b"CONTRIBUTION");
        put_bytes(&mut without_domain, b"NONCE");
        assert_ne!(
            with_domain, without_domain,
            "the domain label must be part of the transcript"
        );
        assert!(
            with_domain.ends_with(&without_domain),
            "the domain label is a prefix field, the rest is unchanged"
        );
    }

    /// Length-prefixing removes the boundary ambiguity between the contribution and the nonce: two different splits of the same concatenated bytes must not hash to the same transcript.
    #[test]
    fn transcript_field_boundaries_are_unambiguous() {
        let a = proof_transcript(b"AB", b"C");
        let b = proof_transcript(b"A", b"BC");
        assert_ne!(
            a, b,
            "shifting the contribution/nonce boundary must not collide"
        );
        assert_eq!(
            [&b"AB"[..], &b"C"[..]].concat(),
            [&b"A"[..], &b"BC"[..]].concat()
        );
    }

    /// A proof is only verifiable under the challenge its prover used: recomputing with a different domain label rejects.
    #[test]
    fn proof_under_a_different_domain_does_not_verify() {
        let claims = sample_claims();
        let kp = generate_keypair(claims.len() as u32).unwrap();
        let sig = sign_credential(&claims, &kp.secret).unwrap();
        let proof = derive_proof(&claims, &sig, &[3], b"nonce-dom").unwrap();
        assert!(verify_proof(&proof, &kp.public, b"nonce-dom"));

        let params = params_for(proof.message_count);
        let p: PoKOfSignatureG1Proof<Bls12_381> = deser(&proof.proof).unwrap();
        let mut revealed_msgs: BTreeMap<usize, Fr> = BTreeMap::new();
        for (i, bytes) in &proof.revealed {
            revealed_msgs.insert(*i as usize, claim_to_fr(bytes));
        }
        let mut contribution = Vec::new();
        p.challenge_contribution(&revealed_msgs, &params, &mut contribution)
            .unwrap();

        let real = challenge(&contribution, b"nonce-dom");
        let mut other_domain = Vec::new();
        put_bytes(&mut other_domain, b"phi-bbs-proof-v2");
        put_bytes(&mut other_domain, &contribution);
        put_bytes(&mut other_domain, b"nonce-dom");
        let forged = compute_random_oracle_challenge::<Fr, Blake2b512>(&other_domain);
        assert_ne!(
            real, forged,
            "a different domain yields a different challenge"
        );
        let pk: PublicKeyG2<Bls12_381> = deser(&kp.public).unwrap();
        assert!(p.verify(&revealed_msgs, &forged, pk, params).is_err());
    }

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
        let proof = derive_proof(&claims, &sig, &[3], b"nonce-1").unwrap();
        assert_eq!(proof.revealed.len(), 1);
        assert_eq!(proof.revealed[0], (3u32, b"over_18=true".to_vec()));
        assert!(verify_proof(&proof, &kp.public, b"nonce-1"));
    }

    /// A repeated revealed index must be refused outright.
    #[test]
    fn rejects_duplicate_revealed_index() {
        let claims = sample_claims();
        let kp = generate_keypair(claims.len() as u32).unwrap();
        let sig = sign_credential(&claims, &kp.secret).unwrap();
        let mut proof = derive_proof(&claims, &sig, &[3], b"nonce-1").unwrap();
        assert!(verify_proof(&proof, &kp.public, b"nonce-1"));

        proof.revealed.push((3u32, b"over_18=false".to_vec()));
        assert!(
            !verify_proof(&proof, &kp.public, b"nonce-1"),
            "a repeated revealed index must be rejected"
        );

        let mut same = derive_proof(&claims, &sig, &[3], b"nonce-1").unwrap();
        same.revealed.push((3u32, b"over_18=true".to_vec()));
        assert!(
            !verify_proof(&same, &kp.public, b"nonce-1"),
            "a repeated index must be rejected even when the values agree"
        );
    }

    /// A revealed index at or beyond the credential's attribute count must be refused.
    #[test]
    fn rejects_out_of_range_revealed_index() {
        let claims = sample_claims();
        let kp = generate_keypair(claims.len() as u32).unwrap();
        let sig = sign_credential(&claims, &kp.secret).unwrap();

        for bad in [claims.len() as u32, claims.len() as u32 + 1, u32::MAX] {
            let mut proof = derive_proof(&claims, &sig, &[3], b"nonce-1").unwrap();
            proof.revealed.push((bad, b"injected".to_vec()));
            assert!(
                !verify_proof(&proof, &kp.public, b"nonce-1"),
                "revealed index {bad} is out of range for {} attributes and must be rejected",
                claims.len()
            );
        }
    }

    /// Revealing every attribute stays valid: the checks above reject malformed sets, not large ones.
    #[test]
    fn accepts_a_well_formed_fully_revealed_proof() {
        let claims = sample_claims();
        let kp = generate_keypair(claims.len() as u32).unwrap();
        let sig = sign_credential(&claims, &kp.secret).unwrap();
        let all: Vec<usize> = (0..claims.len()).collect();

        let proof = derive_proof(&claims, &sig, &all, b"nonce-1").unwrap();
        assert_eq!(proof.revealed.len(), claims.len());
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
        assert!(verify_proof(&p1, &kp.public, b"n"));
        assert!(verify_proof(&p2, &kp.public, b"n"));
    }

    #[test]
    fn deser_rejects_trailing_bytes() {
        let kp = generate_keypair(2).unwrap();
        assert!(deser::<PublicKeyG2<Bls12_381>>(&kp.public).is_ok());
        let mut padded = kp.public.clone();
        padded.push(0u8);
        assert!(
            deser::<PublicKeyG2<Bls12_381>>(&padded).is_err(),
            "trailing padding on a compressed point must be rejected"
        );
    }

    /// The zeroize primitive that the `Zeroizing<Vec<Fr>>` secret wrappers rely on genuinely clears a secret field element to zero — ark-ff's `Fp: Zeroize` wipes the underlying BigInt limbs, so after the wipe the buffer reads as `Fr::zero()`.
    #[test]
    fn secret_field_element_zeroizes_to_zero() {
        use ark_ff::Zero;
        use zeroize::Zeroize;
        let mut secret = claim_to_fr(b"voter_secret=9f2c1a7b4e6d8003");
        assert_ne!(
            secret,
            Fr::zero(),
            "precondition: the secret scalar is non-zero"
        );
        secret.zeroize();
        assert_eq!(
            secret,
            Fr::zero(),
            "Fp::zeroize must clear the secret scalar to zero"
        );
    }
}
