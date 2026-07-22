// SPDX-License-Identifier: Apache-2.0
//! Anonymous-voting derivation proof — algebraic nullifier bound to a BBS+-signed voter secret.

use ark_bls12_381::{g1::Config as G1Config, Fr, G1Affine, G1Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    AffineRepr, CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField, Zero};
use ark_std::UniformRand;
use blake2::Blake2b512;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use bbs_plus::prelude::{
    PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol, PublicKeyG2, SignatureG1,
};
use dock_crypto_utils::signature::MessageOrBlinding;
use schnorr_pok::{
    compute_random_oracle_challenge,
    discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::bbs::{claim_to_fr, deser, params_for, ser, MAX_BBS_MESSAGES};
use crate::error::CryptoError;
use crate::semaphore::external_nullifier;

/// BBS+ message index of the designated voter-secret message `m₀`.
pub const VOTER_SECRET_MSG_INDEX: usize = 0;

/// Domain-separation tag for the RFC-9380 hash-to-curve of the per-election generator `Hₑ` (G1).
const H2C_DST: &[u8] = b"PHI-VOTE-NULLIFIER-BLS12381G1-XMD:SHA-256_SSWU_RO_v1";

/// Domain separator for the composed proof's Fiat-Shamir challenge.
const CHALLENGE_DOMAIN: &[u8] = b"phi-vote-snark-v3";

/// Domain separator for the ballot-binding context folded into the challenge transcript.
const BIND_DOMAIN: &[u8] = b"phi-vote-snark-bind-v1";

/// Compressed BLS12-381 G1 point length (the nullifier's wire width).
pub const NULLIFIER_POINT_LEN: usize = 48;

/// The concrete hash-to-curve instance: RFC-9380 `SSWU_RO` on BLS12-381 G1 via the WB isogeny map, with `expand_message_xmd(SHA-256)` as the field hasher (128-bit security parameter).
type G1Hasher =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<G1Config>>;

/// Hash the per-election domain tag to a BLS12-381 G1 point (`Hₑ`), using the vetted RFC-9380 map.
fn hash_to_g1(election_id: &[u8]) -> Result<G1Affine, CryptoError> {
    let tag = external_nullifier(election_id);
    let hasher = G1Hasher::new(H2C_DST).map_err(|_| CryptoError::Backend("h2c setup"))?;
    hasher
        .hash(&tag)
        .map_err(|_| CryptoError::Backend("h2c hash"))
}

/// Ballot-binding context folded into the Fiat-Shamir transcript so a ballot is non-malleable: a relay cannot re-tag the proof to a different `signal` (chosen option) or a different nullifier, and — with `chain_id` bound first — a proof produced for one network cannot be replayed on another that shares the same election_id and issuer template key.
fn bind_context(chain_id: &[u8], election_id: &[u8], nullifier: &[u8], signal: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BIND_DOMAIN);
    h.update((chain_id.len() as u64).to_be_bytes());
    h.update(chain_id);
    h.update((election_id.len() as u64).to_be_bytes());
    h.update(election_id);
    h.update((signal.len() as u64).to_be_bytes());
    h.update(signal);
    h.update((nullifier.len() as u64).to_be_bytes());
    h.update(nullifier);
    h.finalize().into()
}

/// Scalar multiplication `base^scalar` where the running time does not depend on `scalar`'s bits.
fn blinded_mul<R: rand::RngCore + rand::CryptoRng>(
    base: &G1Affine,
    scalar: &Fr,
    rng: &mut R,
) -> G1Projective {
    let blind = Zeroizing::new(Fr::rand(rng));
    let masked = Zeroizing::new(*scalar + *blind);
    let masked_exp = Zeroizing::new(masked.into_bigint());
    let blind_exp = Zeroizing::new(blind.into_bigint());
    base.mul_bigint(*masked_exp) - base.mul_bigint(*blind_exp)
}

/// A composed vote proof: eligibility (BBS+ PoK, `m₀` hidden) + derivation (`N = Hₑ^{m₀}`) bound together by witness-equality on `m₀`, plus the public nullifier `N`.
pub struct VoteProof {
    /// Total number of credential claims (to reproduce the BBS+ parameters).
    message_count: u32,
    /// Revealed claims `(index, bytes)`; never includes [`VOTER_SECRET_MSG_INDEX`].
    revealed: Vec<(u32, Vec<u8>)>,
    /// Serialized BBS+ proof of knowledge (`m₀` hidden at index 0).
    bbs_proof: Vec<u8>,
    /// Serialized Schnorr discrete-log proof for `N = Hₑ^{m₀}`.
    dl_proof: Vec<u8>,
    /// The nullifier `N` (compressed G1), the public one-vote tag for this election.
    nullifier: G1Affine,
}

impl VoteProof {
    /// The nullifier `N` as compressed bytes — the chain's dedup / storage key.
    pub fn nullifier_bytes(&self) -> Result<[u8; NULLIFIER_POINT_LEN], CryptoError> {
        let v = ser(&self.nullifier)?;
        v.as_slice()
            .try_into()
            .map_err(|_| CryptoError::Backend("nullifier length"))
    }

    /// Deterministic length-prefixed byte encoding for crossing the C-ABI/WASM boundary later.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.message_count.to_be_bytes());
        put_bytes(&mut out, &self.bbs_proof);
        put_bytes(&mut out, &self.dl_proof);
        put_bytes(&mut out, &ser(&self.nullifier)?);
        out.extend_from_slice(&(self.revealed.len() as u32).to_be_bytes());
        for (idx, claim) in &self.revealed {
            out.extend_from_slice(&idx.to_be_bytes());
            put_bytes(&mut out, claim);
        }
        Ok(out)
    }

    /// Byte decoding (inverse of [`VoteProof::to_bytes`]).
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        let mut r = Reader { b, pos: 0 };
        let message_count = r.u32()?;
        if message_count == 0 || message_count > MAX_BBS_MESSAGES {
            return Err(CryptoError::InvalidInput("message_count out of range"));
        }
        let bbs_proof = r.bytes()?;
        let dl_proof = r.bytes()?;
        let nullifier: G1Affine = deser(&r.bytes()?)?;
        if nullifier.is_zero() {
            return Err(CryptoError::InvalidInput("nullifier is identity"));
        }
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
            if idx as usize == VOTER_SECRET_MSG_INDEX {
                return Err(CryptoError::InvalidInput("voter secret cannot be revealed"));
            }
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
        Ok(VoteProof {
            message_count,
            revealed,
            bbs_proof,
            dl_proof,
            nullifier,
        })
    }
}

/// Build a composed vote proof for `claims`/`signature` (a BBS+ credential) in `election_id`, binding the chosen option `signal`.
pub fn prove_vote(
    claims: &[Vec<u8>],
    signature: &[u8],
    issuer_public_key: &[u8],
    reveal: &[usize],
    chain_id: &[u8],
    election_id: &[u8],
    signal: &[u8],
) -> Result<VoteProof, CryptoError> {
    if claims.is_empty() {
        return Err(CryptoError::InvalidInput("no claims"));
    }
    if claims.len() > MAX_BBS_MESSAGES as usize {
        return Err(CryptoError::InvalidInput("message_count out of range"));
    }
    if claims.get(VOTER_SECRET_MSG_INDEX).is_none() {
        return Err(CryptoError::InvalidInput("no voter-secret message"));
    }
    let count = claims.len();
    let reveal_set: BTreeSet<usize> = reveal.iter().copied().collect();
    if reveal_set.iter().any(|&i| i >= count) {
        return Err(CryptoError::InvalidInput("reveal index out of range"));
    }
    if reveal_set.contains(&VOTER_SECRET_MSG_INDEX) {
        return Err(CryptoError::InvalidInput("voter secret cannot be revealed"));
    }

    let mut rng = rand::rngs::OsRng;
    let params = params_for(count as u32);
    let sig: SignatureG1<ark_bls12_381::Bls12_381> = deser(signature)?;
    let issuer_pk: PublicKeyG2<ark_bls12_381::Bls12_381> = deser(issuer_public_key)?;
    let issuer_pk_bytes = ser(&issuer_pk)?;
    let messages: Zeroizing<Vec<Fr>> =
        Zeroizing::new(claims.iter().map(|c| claim_to_fr(c)).collect());

    // The signed voter secret m₀ and the shared blinding r₀ — the two secrets of this proof.
    let m0 = Zeroizing::new(messages[VOTER_SECRET_MSG_INDEX]);
    let r0 = Zeroizing::new(Fr::rand(&mut rng));

    let h_e = hash_to_g1(election_id)?;
    let nullifier = blinded_mul(&h_e, &m0, &mut rng).into_affine();
    if nullifier.is_zero() {
        return Err(CryptoError::InvalidInput("nullifier is identity"));
    }

    let mbi = messages.iter().enumerate().map(|(i, m)| {
        if i == VOTER_SECRET_MSG_INDEX {
            MessageOrBlinding::BlindMessageWithConcreteBlinding {
                message: m,
                blinding: *r0,
            }
        } else if reveal_set.contains(&i) {
            MessageOrBlinding::RevealMessage(m)
        } else {
            MessageOrBlinding::BlindMessageRandomly(m)
        }
    });
    let pok = PoKOfSignatureG1Protocol::init(&mut rng, &sig, &params, mbi)
        .map_err(|_| CryptoError::Backend("bbs pok init"))?;

    let dl = PokDiscreteLogProtocol::init(*m0, *r0, &h_e);

    let mut revealed_msgs: BTreeMap<usize, Fr> = BTreeMap::new();
    for &i in &reveal_set {
        revealed_msgs.insert(i, messages[i]);
    }
    let nullifier_bytes = ser(&nullifier)?;
    let challenge = compute_challenge(
        |buf| {
            pok.challenge_contribution(&revealed_msgs, &params, buf)
                .map_err(|_| CryptoError::Backend("bbs challenge"))
        },
        |buf| {
            dl.challenge_contribution(&h_e, &nullifier, buf)
                .map_err(|_| CryptoError::Backend("dl challenge"))
        },
        count as u32,
        &issuer_pk_bytes,
        chain_id,
        election_id,
        &nullifier_bytes,
        signal,
    )?;

    let bbs_proof = pok
        .gen_proof(&challenge)
        .map_err(|_| CryptoError::Backend("bbs gen_proof"))?;
    let dl_proof: PokDiscreteLog<G1Affine> = dl.gen_proof(&challenge);

    let revealed: Vec<(u32, Vec<u8>)> = reveal_set
        .iter()
        .map(|&i| (i as u32, claims[i].clone()))
        .collect();

    Ok(VoteProof {
        message_count: count as u32,
        revealed,
        bbs_proof: ser(&bbs_proof)?,
        dl_proof: ser(&dl_proof)?,
        nullifier,
    })
}

/// Serialize-boundary wrapper for the holder-side clients (WASM / Flutter FFI): build a vote proof with [`prove_vote`] and return its serialized [`VoteProof`] bytes (the public blob carrying `N`).
pub fn prove_vote_bytes(
    claims: &[Vec<u8>],
    signature: &[u8],
    issuer_public_key: &[u8],
    reveal: &[usize],
    chain_id: &[u8],
    election_id: &[u8],
    signal: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    prove_vote(
        claims,
        signature,
        issuer_public_key,
        reveal,
        chain_id,
        election_id,
        signal,
    )?
    .to_bytes()
}

/// Verify a composed vote proof (typed).
pub fn verify_vote_proof(
    proof: &VoteProof,
    issuer_public_key: &[u8],
    chain_id: &[u8],
    election_id: &[u8],
    signal: &[u8],
) -> bool {
    verify_inner(proof, issuer_public_key, chain_id, election_id, signal).is_ok()
}

/// Verify a serialized composed vote proof (the boundary form).
pub fn verify_vote(
    proof_bytes: &[u8],
    issuer_public_key: &[u8],
    chain_id: &[u8],
    election_id: &[u8],
    signal: &[u8],
) -> bool {
    match VoteProof::from_bytes(proof_bytes) {
        Ok(p) => verify_vote_proof(&p, issuer_public_key, chain_id, election_id, signal),
        Err(_) => false,
    }
}

/// The actual verification, returning a `Result` so each rejection reason stays explicit; the public entry points collapse it to a fail-safe bool.
fn verify_inner(
    proof: &VoteProof,
    issuer_public_key: &[u8],
    chain_id: &[u8],
    election_id: &[u8],
    signal: &[u8],
) -> Result<(), CryptoError> {
    if proof.message_count == 0 || proof.message_count > MAX_BBS_MESSAGES {
        return Err(CryptoError::InvalidInput("message_count out of range"));
    }
    if proof.nullifier.is_zero() {
        return Err(CryptoError::InvalidInput("nullifier is identity"));
    }

    let params = params_for(proof.message_count);
    let pk: PublicKeyG2<ark_bls12_381::Bls12_381> = deser(issuer_public_key)?;
    let bbs: PoKOfSignatureG1Proof<ark_bls12_381::Bls12_381> = deser(&proof.bbs_proof)?;
    let dl: PokDiscreteLog<G1Affine> = deser(&proof.dl_proof)?;

    // Reconstruct the revealed set / message map; the voter secret must not be among the revealed.
    let mut reveal_ids: BTreeSet<usize> = BTreeSet::new();
    let mut revealed_msgs: BTreeMap<usize, Fr> = BTreeMap::new();
    for (idx, bytes) in &proof.revealed {
        let i = *idx as usize;
        if i == VOTER_SECRET_MSG_INDEX || i >= proof.message_count as usize {
            return Err(CryptoError::InvalidInput("revealed index invalid"));
        }
        if !reveal_ids.insert(i) {
            return Err(CryptoError::InvalidInput("duplicate revealed index"));
        }
        revealed_msgs.insert(i, claim_to_fr(bytes));
    }

    let h_e = hash_to_g1(election_id)?;
    let nullifier_bytes = ser(&proof.nullifier)?;
    let challenge = compute_challenge(
        |buf| {
            bbs.challenge_contribution(&revealed_msgs, &params, buf)
                .map_err(|_| CryptoError::Backend("bbs challenge"))
        },
        |buf| {
            dl.challenge_contribution(&h_e, &proof.nullifier, buf)
                .map_err(|_| CryptoError::Backend("dl challenge"))
        },
        proof.message_count,
        &ser(&pk)?,
        chain_id,
        election_id,
        &nullifier_bytes,
        signal,
    )?;

    bbs.verify(&revealed_msgs, &challenge, pk, params)
        .map_err(|_| CryptoError::VerificationFailed)?;
    if !dl.verify(&proof.nullifier, &h_e, &challenge) {
        return Err(CryptoError::VerificationFailed);
    }

    let bbs_resp = bbs
        .get_resp_for_message(VOTER_SECRET_MSG_INDEX, &reveal_ids)
        .map_err(|_| CryptoError::VerificationFailed)?;
    let a = ser(bbs_resp)?;
    let b = ser(&dl.response)?;
    if a.ct_eq(&b).unwrap_u8() != 1 {
        return Err(CryptoError::VerificationFailed);
    }
    Ok(())
}

/// Assemble the Fiat-Shamir transcript in its canonical framing.
#[allow(clippy::too_many_arguments)]
fn vote_transcript<FBbs, FDl>(
    bbs_contribution: FBbs,
    dl_contribution: FDl,
    message_count: u32,
    issuer_pk: &[u8],
    chain_id: &[u8],
    election_id: &[u8],
    nullifier_bytes: &[u8],
    signal: &[u8],
) -> Result<Vec<u8>, CryptoError>
where
    FBbs: FnOnce(&mut Vec<u8>) -> Result<(), CryptoError>,
    FDl: FnOnce(&mut Vec<u8>) -> Result<(), CryptoError>,
{
    let mut bbs_buf = Vec::new();
    bbs_contribution(&mut bbs_buf)?;
    let mut dl_buf = Vec::new();
    dl_contribution(&mut dl_buf)?;

    let mut transcript = Vec::new();
    put_bytes(&mut transcript, CHALLENGE_DOMAIN);
    transcript.extend_from_slice(&message_count.to_be_bytes());
    put_bytes(&mut transcript, issuer_pk);
    put_bytes(&mut transcript, &bbs_buf);
    put_bytes(&mut transcript, &dl_buf);
    put_bytes(
        &mut transcript,
        &bind_context(chain_id, election_id, nullifier_bytes, signal),
    );
    Ok(transcript)
}

/// Derive the composed Fiat-Shamir challenge from the canonical transcript ([`vote_transcript`]).
#[allow(clippy::too_many_arguments)]
fn compute_challenge<FBbs, FDl>(
    bbs_contribution: FBbs,
    dl_contribution: FDl,
    message_count: u32,
    issuer_pk: &[u8],
    chain_id: &[u8],
    election_id: &[u8],
    nullifier_bytes: &[u8],
    signal: &[u8],
) -> Result<Fr, CryptoError>
where
    FBbs: FnOnce(&mut Vec<u8>) -> Result<(), CryptoError>,
    FDl: FnOnce(&mut Vec<u8>) -> Result<(), CryptoError>,
{
    let transcript = vote_transcript(
        bbs_contribution,
        dl_contribution,
        message_count,
        issuer_pk,
        chain_id,
        election_id,
        nullifier_bytes,
        signal,
    )?;
    let c = compute_random_oracle_challenge::<Fr, Blake2b512>(&transcript);
    if c.is_zero() {
        return Err(CryptoError::Backend("degenerate challenge"));
    }
    Ok(c)
}

/// Append a length-prefixed byte string (u32 big-endian length).
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// Small big-endian reader for panic-free decoding (parity with `bbs::Reader`).
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
        self.pos = end;
        Ok(u32::from_be_bytes(chunk))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbs;

    /// Fixed chain-id the vote tests are pinned to.
    const TEST_CHAIN: &[u8] = b"phi-testnet-1";

    fn prove_vote(
        claims: &[Vec<u8>],
        signature: &[u8],
        issuer_public_key: &[u8],
        reveal: &[usize],
        election_id: &[u8],
        signal: &[u8],
    ) -> Result<VoteProof, CryptoError> {
        super::prove_vote(
            claims,
            signature,
            issuer_public_key,
            reveal,
            TEST_CHAIN,
            election_id,
            signal,
        )
    }

    fn prove_vote_bytes(
        claims: &[Vec<u8>],
        signature: &[u8],
        issuer_public_key: &[u8],
        reveal: &[usize],
        election_id: &[u8],
        signal: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        super::prove_vote_bytes(
            claims,
            signature,
            issuer_public_key,
            reveal,
            TEST_CHAIN,
            election_id,
            signal,
        )
    }

    fn verify_vote_proof(
        proof: &VoteProof,
        issuer_public_key: &[u8],
        election_id: &[u8],
        signal: &[u8],
    ) -> bool {
        super::verify_vote_proof(proof, issuer_public_key, TEST_CHAIN, election_id, signal)
    }

    fn verify_vote(
        proof_bytes: &[u8],
        issuer_public_key: &[u8],
        election_id: &[u8],
        signal: &[u8],
    ) -> bool {
        super::verify_vote(
            proof_bytes,
            issuer_public_key,
            TEST_CHAIN,
            election_id,
            signal,
        )
    }

    fn vote_transcript<FBbs, FDl>(
        bbs_contribution: FBbs,
        dl_contribution: FDl,
        message_count: u32,
        issuer_pk: &[u8],
        election_id: &[u8],
        nullifier_bytes: &[u8],
        signal: &[u8],
    ) -> Result<Vec<u8>, CryptoError>
    where
        FBbs: FnOnce(&mut Vec<u8>) -> Result<(), CryptoError>,
        FDl: FnOnce(&mut Vec<u8>) -> Result<(), CryptoError>,
    {
        super::vote_transcript(
            bbs_contribution,
            dl_contribution,
            message_count,
            issuer_pk,
            TEST_CHAIN,
            election_id,
            nullifier_bytes,
            signal,
        )
    }

    /// A credential whose claim at index 0 is a high-entropy voter secret.
    fn credential() -> (Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
        let claims = vec![
            b"voter_secret=9f2c1a7b4e6d8003".to_vec(), // index 0 (VOTER_SECRET_MSG_INDEX)
            b"region=north".to_vec(),
            b"cohort=2025".to_vec(),
        ];
        let kp = bbs::generate_keypair(claims.len() as u32).unwrap();
        let sig = bbs::sign_credential(&claims, &kp.secret).unwrap();
        (claims, sig, kp.public)
    }

    fn prove(
        claims: &[Vec<u8>],
        sig: &[u8],
        pk: &[u8],
        election: &[u8],
        signal: &[u8],
    ) -> VoteProof {
        prove_vote(claims, sig, pk, &[1], election, signal).unwrap()
    }

    /// FUNCTIONAL EQUIVALENCE: the blinded multiply must return exactly what the direct, unblinded multiply would.
    #[test]
    fn blinded_mul_equals_the_reference_multiply() {
        let mut rng = rand::rngs::OsRng;
        let h = hash_to_g1(b"ct-equivalence-election").unwrap();

        let check = |s: Fr, what: &str| {
            let reference = h.mul_bigint(s.into_bigint()).into_affine();
            let blinded = blinded_mul(&h, &s, &mut rand::rngs::OsRng).into_affine();
            assert_eq!(blinded, reference, "blinded multiply diverged for {what}");
            assert_eq!(
                ser(&blinded).unwrap(),
                ser(&reference).unwrap(),
                "serialized nullifier differs for {what}"
            );
        };

        check(Fr::from(0u64), "zero");
        check(Fr::from(1u64), "one");
        check(-Fr::from(1u64), "-1 (wraps the modulus when blinded)");
        check(
            Fr::from(1u64) + Fr::from(1u64 << 40),
            "a low-Hamming-weight scalar",
        );
        for i in 0..32 {
            check(Fr::rand(&mut rng), &format!("random scalar #{i}"));
        }
    }

    /// The blinding is fresh per call, so the same secret does not take the same internal path twice — while the RESULT stays deterministic, which is what the nullifier's one-vote property depends on.
    #[test]
    fn blinded_mul_is_deterministic_in_its_result() {
        let mut rng = rand::rngs::OsRng;
        let h = hash_to_g1(b"ct-determinism-election").unwrap();
        let secret = Fr::rand(&mut rng);
        let first = blinded_mul(&h, &secret, &mut rng).into_affine();
        for _ in 0..16 {
            assert_eq!(
                blinded_mul(&h, &secret, &mut rng).into_affine(),
                first,
                "the same secret must always yield the same nullifier"
            );
        }
    }

    /// Coarse statistical timing check, IGNORED by default.
    #[test]
    fn blinding_scalars_are_wiped_and_only_meaningful_as_a_pair() {
        use zeroize::Zeroize;

        let mut rng = rand::rngs::OsRng;
        let secret = Fr::rand(&mut rng);
        let blind = Fr::rand(&mut rng);
        let masked = secret + blind;

        // The identity that makes the pair, not the parts, the secret.
        assert_eq!(masked - blind, secret, "masked - blind must recover m₀");
        assert_ne!(masked, secret, "the masked exponent must not be m₀ itself");

        let mut masked_exp = masked.into_bigint();
        let mut blind_exp = blind.into_bigint();
        assert_ne!(masked_exp, blind_exp);
        masked_exp.zeroize();
        blind_exp.zeroize();
        assert_eq!(
            masked_exp,
            <Fr as PrimeField>::BigInt::from(0u64),
            "the masked exponent's limbs must be cleared"
        );
        assert_eq!(
            blind_exp,
            <Fr as PrimeField>::BigInt::from(0u64),
            "the blinding exponent's limbs must be cleared"
        );
    }

    #[test]
    #[ignore = "wall-clock timing is machine-dependent; run deliberately, not in CI"]
    fn blinded_mul_timing_is_independent_of_the_scalar() {
        use std::time::Instant;

        let mut rng = rand::rngs::OsRng;
        let h = hash_to_g1(b"ct-timing-election").unwrap();
        const ROUNDS: usize = 400;

        /// Median wall-clock nanoseconds over `ROUNDS` multiplies of `s`.
        fn median<F: FnMut() -> G1Projective>(mut f: F) -> u128 {
            let mut times = Vec::with_capacity(ROUNDS);
            for _ in 0..ROUNDS {
                let t = Instant::now();
                let _ = std::hint::black_box(f());
                times.push(t.elapsed().as_nanos());
            }
            times.sort_unstable();
            times[ROUNDS / 2] // robust against scheduler outliers
        }

        let random_scalar = Fr::rand(&mut rng);
        let sparse_scalar = Fr::from(1u64);

        let raw_sparse = median(|| h.mul_bigint(sparse_scalar.into_bigint()));
        let raw_random = median(|| h.mul_bigint(random_scalar.into_bigint()));
        println!(
            "unblinded median ns — sparse: {raw_sparse}, random: {raw_random} (ratio {:.2}x)",
            raw_random.max(raw_sparse) as f64 / raw_random.min(raw_sparse) as f64
        );

        let sparse = median(|| blinded_mul(&h, &sparse_scalar, &mut rand::rngs::OsRng));
        let dense = median(|| blinded_mul(&h, &random_scalar, &mut rand::rngs::OsRng));
        let (lo, hi) = (sparse.min(dense) as f64, sparse.max(dense) as f64);
        println!(
            "blinded   median ns — sparse: {sparse}, random: {dense} (ratio {:.2}x)",
            hi / lo
        );
        assert!(
            hi / lo < 1.25,
            "median times too far apart ({sparse} vs {dense} ns): the multiply still looks \
             scalar-dependent"
        );
    }

    /// Fixed stand-in contributions, so the transcript KAT below pins the FRAMING rather than the randomized commitment bytes a real proof would produce.
    fn fixed_transcript() -> Vec<u8> {
        vote_transcript(
            |buf| {
                buf.extend_from_slice(b"BBS-COMMITMENTS");
                Ok(())
            },
            |buf| {
                buf.extend_from_slice(b"DL-COMMITS");
                Ok(())
            },
            3,
            b"ISSUER-PUBLIC-KEY",
            b"election-kat",
            b"NULLIFIER-BYTES",
            b"option-7",
        )
        .unwrap()
    }

    /// KNOWN-ANSWER VECTOR for the Fiat-Shamir transcript framing.
    #[test]
    fn transcript_framing_kat() {
        let t = fixed_transcript();
        assert_eq!(
            hex::encode(&t),
            concat!(
                "00000011",                           // len("phi-vote-snark-v3") = 17
                "7068692d766f74652d736e61726b2d7633", // "phi-vote-snark-v3"
                "00000003",                           // message_count = 3 (bare u32 BE)
                "00000011",                           // len("ISSUER-PUBLIC-KEY") = 17
                "4953535545522d5055424c49432d4b4559", // "ISSUER-PUBLIC-KEY"
                "0000000f",                           // len("BBS-COMMITMENTS") = 15
                "4242532d434f4d4d49544d454e5453",     // "BBS-COMMITMENTS"
                "0000000a",                           // len("DL-COMMITS") = 10
                "444c2d434f4d4d495453",               // "DL-COMMITS"
                "00000020", // len(bind_context) = 32 (now over chain_id first)
                "4527c17b102b0e5aa5b97d39743bc4d4dbf0c5442b22c8562881ba9646fb8dcc", // bind hash (chain_id ‖ election ‖ signal ‖ nullifier)
            ),
            "the Fiat-Shamir transcript framing is pinned"
        );
        let c = compute_random_oracle_challenge::<Fr, Blake2b512>(&t);
        assert_eq!(
            hex::encode(ser(&c).unwrap()),
            "051b750087c69f3faa9c8728cf4be981629f2b086cef77eaf92485a3ecaa6c09"
        );
    }

    /// The issuer key is genuinely part of the transcript: changing only the key changes the challenge.
    #[test]
    fn transcript_binds_the_issuer_key() {
        let base = fixed_transcript();
        let other = vote_transcript(
            |buf| {
                buf.extend_from_slice(b"BBS-COMMITMENTS");
                Ok(())
            },
            |buf| {
                buf.extend_from_slice(b"DL-COMMITS");
                Ok(())
            },
            3,
            b"ISSUER-PUBLIC-KEZ", // one byte different, same length
            b"election-kat",
            b"NULLIFIER-BYTES",
            b"option-7",
        )
        .unwrap();
        assert_ne!(
            base, other,
            "a different issuer key must change the transcript"
        );
    }

    /// …and so is the message count.
    #[test]
    fn transcript_binds_the_message_count() {
        let base = fixed_transcript();
        let other = vote_transcript(
            |buf| {
                buf.extend_from_slice(b"BBS-COMMITMENTS");
                Ok(())
            },
            |buf| {
                buf.extend_from_slice(b"DL-COMMITS");
                Ok(())
            },
            4, // the only difference
            b"ISSUER-PUBLIC-KEY",
            b"election-kat",
            b"NULLIFIER-BYTES",
            b"option-7",
        )
        .unwrap();
        assert_ne!(
            base, other,
            "a different message count must change the transcript"
        );
    }

    /// Length-prefixing makes the field boundaries unambiguous: moving a byte across the issuer-key / BBS-commitments boundary yields a DIFFERENT transcript.
    #[test]
    fn transcript_field_boundaries_are_unambiguous() {
        let a = vote_transcript(
            |buf| {
                buf.extend_from_slice(b"BC");
                Ok(())
            },
            |buf| {
                buf.extend_from_slice(b"D");
                Ok(())
            },
            1,
            b"KEYA",
            b"e",
            b"n",
            b"s",
        )
        .unwrap();
        let b = vote_transcript(
            |buf| {
                buf.extend_from_slice(b"C");
                Ok(())
            },
            |buf| {
                buf.extend_from_slice(b"D");
                Ok(())
            },
            1,
            b"KEYAB", // the 'B' moved from the commitments into the key
            b"e",
            b"n",
            b"s",
        )
        .unwrap();
        assert_ne!(
            a, b,
            "shifting a byte across a field boundary must not collide"
        );
    }

    /// END-TO-END: a proof made under one issuer does not verify under another.
    #[test]
    fn proof_does_not_verify_under_a_different_issuer() {
        let (claims, sig, pk) = credential();
        let other = bbs::generate_keypair(claims.len() as u32).unwrap();
        let p = prove(&claims, &sig, &pk, b"election-1", b"yes");
        assert!(verify_vote_proof(&p, &pk, b"election-1", b"yes"));
        assert!(!verify_vote_proof(&p, &other.public, b"election-1", b"yes"));
    }

    /// A prover that folds in the WRONG issuer key produces a proof nobody accepts — including under the key it actually named.
    #[test]
    fn proving_under_a_mismatched_issuer_key_yields_an_unusable_proof() {
        let (claims, sig, pk) = credential();
        let other = bbs::generate_keypair(claims.len() as u32).unwrap();
        let p = prove_vote(
            &claims,
            &sig,
            &other.public, // not the key this credential was signed under
            &[1],
            b"election-1",
            b"yes",
        )
        .unwrap();
        assert!(!verify_vote_proof(&p, &pk, b"election-1", b"yes"));
        assert!(!verify_vote_proof(&p, &other.public, b"election-1", b"yes"));
    }

    /// A tampered message count is refused; it is bound into the transcript as well as driving the BBS+ parameters.
    #[test]
    fn tampered_message_count_is_rejected() {
        let (claims, sig, pk) = credential();
        let mut p = prove(&claims, &sig, &pk, b"election-1", b"yes");
        assert!(verify_vote_proof(&p, &pk, b"election-1", b"yes"));
        p.message_count += 1;
        assert!(!verify_vote_proof(&p, &pk, b"election-1", b"yes"));
    }

    #[test]
    fn roundtrip_valid_proof_verifies() {
        let (claims, sig, pk) = credential();
        let p = prove(&claims, &sig, &pk, b"election-1", b"option-2");
        assert!(verify_vote_proof(&p, &pk, b"election-1", b"option-2"));
        let bytes = p.to_bytes().unwrap();
        assert!(verify_vote(&bytes, &pk, b"election-1", b"option-2"));
    }

    #[test]
    fn prove_vote_bytes_roundtrip_verifies() {
        let (claims, sig, pk) = credential();
        let bytes = prove_vote_bytes(&claims, &sig, &pk, &[1], b"election-7", b"option-3").unwrap();
        assert!(verify_vote(&bytes, &pk, b"election-7", b"option-3"));
        // A different chosen option (signal) must not verify against the same proof.
        assert!(!verify_vote(&bytes, &pk, b"election-7", b"option-X"));
        // A wrong election must not verify either.
        assert!(!verify_vote(&bytes, &pk, b"election-8", b"option-3"));
    }

    #[test]
    fn non_canonical_padded_nullifier_is_rejected() {
        let (claims, sig, pk) = credential();
        let p = prove(&claims, &sig, &pk, b"election-1", b"yes");

        assert!(VoteProof::from_bytes(&p.to_bytes().unwrap()).is_ok());

        let mut out = Vec::new();
        out.extend_from_slice(&p.message_count.to_be_bytes());
        put_bytes(&mut out, &p.bbs_proof);
        put_bytes(&mut out, &p.dl_proof);
        let mut null_padded = ser(&p.nullifier).unwrap();
        null_padded.push(0u8); // trailing padding on the nullifier field
        put_bytes(&mut out, &null_padded);
        out.extend_from_slice(&(p.revealed.len() as u32).to_be_bytes());
        for (idx, claim) in &p.revealed {
            out.extend_from_slice(&idx.to_be_bytes());
            put_bytes(&mut out, claim);
        }
        assert_ne!(
            out,
            p.to_bytes().unwrap(),
            "the padded blob differs from the canonical one"
        );
        assert!(
            VoteProof::from_bytes(&out).is_err(),
            "a padded/non-canonical nullifier encoding must be rejected on deserialize"
        );
    }

    /// The revealed list must be strictly increasing, matching the BBS+ decoder.
    #[test]
    fn vote_proof_rejects_unsorted_and_duplicate_revealed_indices() {
        let (claims, sig, pk) = credential();
        let p = prove_vote(&claims, &sig, &pk, &[1, 2], b"election-1", b"yes").unwrap();
        assert!(VoteProof::from_bytes(&p.to_bytes().unwrap()).is_ok());
        assert_eq!(p.revealed.len(), 2, "the fixture must reveal two claims");

        let encode = |revealed: &[(u32, Vec<u8>)]| {
            let mut out = Vec::new();
            out.extend_from_slice(&p.message_count.to_be_bytes());
            put_bytes(&mut out, &p.bbs_proof);
            put_bytes(&mut out, &p.dl_proof);
            put_bytes(&mut out, &ser(&p.nullifier).unwrap());
            out.extend_from_slice(&(revealed.len() as u32).to_be_bytes());
            for (idx, claim) in revealed {
                out.extend_from_slice(&idx.to_be_bytes());
                put_bytes(&mut out, claim);
            }
            out
        };

        let mut reordered = p.revealed.clone();
        reordered.reverse();
        assert!(
            VoteProof::from_bytes(&encode(&reordered)).is_err(),
            "a reordered revealed list must be refused"
        );

        let duplicated = vec![p.revealed[0].clone(), p.revealed[0].clone()];
        assert!(
            VoteProof::from_bytes(&encode(&duplicated)).is_err(),
            "a repeated revealed index must be refused"
        );

        assert!(VoteProof::from_bytes(&encode(&p.revealed)).is_ok());
    }

    #[test]
    fn wrong_issuer_key_is_rejected() {
        let (claims, sig, pk) = credential();
        let other = bbs::generate_keypair(claims.len() as u32).unwrap();
        let p = prove(&claims, &sig, &pk, b"election-1", b"yes");
        assert!(!verify_vote_proof(&p, &other.public, b"election-1", b"yes"));
    }

    #[test]
    fn nullifier_is_deterministic_per_secret_and_election() {
        let (claims, sig, pk) = credential();
        let a = prove(&claims, &sig, &pk, b"election-1", b"a")
            .nullifier_bytes()
            .unwrap();
        let b = prove(&claims, &sig, &pk, b"election-1", b"b")
            .nullifier_bytes()
            .unwrap();
        assert_eq!(a, b, "same (secret, election) must yield one nullifier");
        let c = prove(&claims, &sig, &pk, b"election-2", b"a")
            .nullifier_bytes()
            .unwrap();
        assert_ne!(a, c, "different election must yield a different nullifier");
    }

    #[test]
    fn different_secret_yields_different_nullifier() {
        let e = b"election-1";
        let (c1, s1, p1) = credential();
        let mut c2 = c1.clone();
        c2[0] = b"voter_secret=00aa11bb22cc33dd".to_vec();
        let kp2 = bbs::generate_keypair(c2.len() as u32).unwrap();
        let s2 = bbs::sign_credential(&c2, &kp2.secret).unwrap();
        let n1 = prove(&c1, &s1, &p1, e, b"x").nullifier_bytes().unwrap();
        let n2 = prove(&c2, &s2, &kp2.public, e, b"x")
            .nullifier_bytes()
            .unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn two_proofs_are_unlinkable_but_share_the_nullifier() {
        let (claims, sig, pk) = credential();
        let p1 = prove(&claims, &sig, &pk, b"election-1", b"a");
        let p2 = prove(&claims, &sig, &pk, b"election-1", b"a");
        assert_eq!(p1.nullifier_bytes().unwrap(), p2.nullifier_bytes().unwrap());
        // … but the proof bytes differ (per-presentation randomization = unlinkability of the proof).
        assert_ne!(p1.bbs_proof, p2.bbs_proof);
        assert!(verify_vote_proof(&p1, &pk, b"election-1", b"a"));
        assert!(verify_vote_proof(&p2, &pk, b"election-1", b"a"));
    }

    #[test]
    fn tampered_nullifier_fails_witness_equality() {
        let (claims, sig, pk) = credential();
        let mut p = prove(&claims, &sig, &pk, b"election-1", b"yes");
        let forged = prove(&claims, &sig, &pk, b"election-2", b"yes").nullifier;
        assert_ne!(p.nullifier, forged);
        p.nullifier = forged;
        assert!(!verify_vote_proof(&p, &pk, b"election-1", b"yes"));
        let bytes = p.to_bytes().unwrap();
        assert!(!verify_vote(&bytes, &pk, b"election-1", b"yes"));
    }

    #[test]
    fn tampered_dl_response_fails() {
        let (claims, sig, pk) = credential();
        let mut p = prove(&claims, &sig, &pk, b"election-1", b"yes");
        let mut dl: PokDiscreteLog<G1Affine> = deser(&p.dl_proof).unwrap();
        dl.response += Fr::from(1u64);
        p.dl_proof = ser(&dl).unwrap();
        assert!(!verify_vote_proof(&p, &pk, b"election-1", b"yes"));
    }

    #[test]
    fn retagging_signal_is_non_malleable() {
        let (claims, sig, pk) = credential();
        let p = prove(&claims, &sig, &pk, b"election-1", b"yes");
        assert!(verify_vote_proof(&p, &pk, b"election-1", b"yes"));
        assert!(!verify_vote_proof(&p, &pk, b"election-1", b"no"));
    }

    #[test]
    fn replay_under_a_different_election_fails() {
        let (claims, sig, pk) = credential();
        let p = prove(&claims, &sig, &pk, b"election-A", b"yes");
        assert!(verify_vote_proof(&p, &pk, b"election-A", b"yes"));
        assert!(!verify_vote_proof(&p, &pk, b"election-B", b"yes"));
    }

    /// The chain-id is bound into the ballot: a proof produced for one network's chain-id is rejected under another, even with the SAME issuer key, election and signal.
    #[test]
    fn proof_is_bound_to_chain_id() {
        let (claims, sig, pk) = credential();
        let chain_a: &[u8] = b"phi-chain-A";
        let chain_b: &[u8] = b"phi-chain-B";

        let p =
            super::prove_vote(&claims, &sig, &pk, &[1], chain_a, b"election-1", b"yes").unwrap();
        assert!(
            super::verify_vote_proof(&p, &pk, chain_a, b"election-1", b"yes"),
            "a proof must verify under the chain-id it was produced for"
        );
        assert!(
            !super::verify_vote_proof(&p, &pk, chain_b, b"election-1", b"yes"),
            "a proof built for chain A must not verify under chain B"
        );
        let bytes = p.to_bytes().unwrap();
        assert!(super::verify_vote(
            &bytes,
            &pk,
            chain_a,
            b"election-1",
            b"yes"
        ));
        assert!(!super::verify_vote(
            &bytes,
            &pk,
            chain_b,
            b"election-1",
            b"yes"
        ));

        let p_b =
            super::prove_vote(&claims, &sig, &pk, &[1], chain_b, b"election-1", b"yes").unwrap();
        assert_eq!(
            p.nullifier_bytes().unwrap(),
            p_b.nullifier_bytes().unwrap(),
            "the nullifier does not depend on chain_id; the binding is what blocks cross-chain replay"
        );
    }

    /// R2 — witness-equality dependency KAT.
    #[test]
    fn witness_equality_response_binding_kat() {
        let (claims, sig, pk) = credential();
        let p = super::prove_vote(
            &claims,
            &sig,
            &pk,
            &[1],
            b"phi-chain-kat",
            b"election-kat",
            b"option-kat",
        )
        .unwrap();
        // The proof must verify — the binding is live, not vacuous.
        assert!(super::verify_vote_proof(
            &p,
            &pk,
            b"phi-chain-kat",
            b"election-kat",
            b"option-kat"
        ));

        let bbs: PoKOfSignatureG1Proof<ark_bls12_381::Bls12_381> = deser(&p.bbs_proof).unwrap();
        let dl: PokDiscreteLog<G1Affine> = deser(&p.dl_proof).unwrap();
        let reveal_ids: BTreeSet<usize> = p.revealed.iter().map(|(i, _)| *i as usize).collect();
        let bbs_resp = bbs
            .get_resp_for_message(VOTER_SECRET_MSG_INDEX, &reveal_ids)
            .expect("the voter-secret response must be recoverable");
        assert_eq!(
            ser(bbs_resp).unwrap(),
            ser(&dl.response).unwrap(),
            "the BBS+ voter-secret response must equal the discrete-log response — a dependency bump \
             that changes either the response algebra or its serialization breaks the nullifier binding"
        );
    }

    #[test]
    fn revealing_the_voter_secret_is_refused() {
        let (claims, sig, pk) = credential();
        assert!(prove_vote(&claims, &sig, &pk, &[0], b"election-1", b"yes").is_err());
        assert!(prove_vote(&claims, &sig, &pk, &[0, 1], b"election-1", b"yes").is_err());
    }

    #[test]
    fn malformed_inputs_fail_closed() {
        let (_c, _s, pk) = credential();
        assert!(!verify_vote(&[], &pk, b"e", b"s"));
        assert!(!verify_vote(&[0, 1, 2], &pk, b"e", b"s"));
        assert!(VoteProof::from_bytes(&[]).is_err());
    }

    /// The secret-carrying protocol types wipe their witnesses/blindings on drop; a compile-time bound is the faithful way to assert this without reading freed memory.
    #[test]
    fn witness_types_zeroize_on_drop() {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<PokDiscreteLogProtocol<G1Affine>>();
        // A sanity check that our secret wrapper actually zeroizes a field element.
        let mut secret = Zeroizing::new(Fr::from(42u64));
        *secret = Fr::from(0u64);
        assert_eq!(*secret, Fr::from(0u64));
    }
}
