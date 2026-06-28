// SPDX-License-Identifier: Apache-2.0
//! Semaphore-style nullifier binding for anonymous one-human-one-vote.
//!
//! Threat model and what this module guarantees:
//!
//! - [`voting::compute_nullifier`](crate::voting::compute_nullifier) makes a per-(secret, election)
//!   tag that collapses a voter's repeat votes to one. On its own it does *not* stop a holder who
//!   knows two eligible secrets from minting two nullifiers, and it does not prove the nullifier was
//!   derived from a *signed* credential.
//! - This module adds the **binding** layer: the BBS eligibility proof is verified against a
//!   presentation header that is a function of `(election_id, nullifier, signal)` ([`bind_nonce`]),
//!   where `signal` is the voter's chosen option. A third party therefore cannot replay an
//!   eligibility proof under a different nullifier, the proof commits to exactly one nullifier per
//!   presentation, and — because the chosen option is folded into the header — the accepted ballot is
//!   non-malleable: a relay cannot re-tag the proof to a different choice.
//!
//! Full soundness (one *credential* → exactly one accepted nullifier per election, with cross-election
//! unlinkability) additionally requires proving in zero knowledge that `nullifier = H(secret, election)`
//! for a `secret` that is a signed claim of the credential. That derivation proof needs a SNARK over
//! the hash relation (a vetted Semaphore/arkworks circuit, vendored) and is tracked as the remaining
//! step; this module deliberately stops at the binding layer so nothing is hand-rolled here.

use sha2::{Digest, Sha256};

use crate::voting::{compute_nullifier, NULLIFIER_LEN};

/// External nullifier (the per-election domain): `H("phi-extnull-v1" || len(election_id) || election_id)`.
/// Using a fixed-width digest as the voting topic keeps every election's nullifier space disjoint.
pub fn external_nullifier(election_id: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"phi-extnull-v1");
    h.update((election_id.len() as u64).to_be_bytes());
    h.update(election_id);
    h.finalize().into()
}

/// The voter's nullifier for an election: `compute_nullifier(secret, external_nullifier(election_id))`.
/// Deterministic per (secret, election); uncorrelated across elections while the secret stays private.
pub fn nullifier(secret: &[u8], election_id: &[u8]) -> [u8; NULLIFIER_LEN] {
    compute_nullifier(secret, &external_nullifier(election_id))
}

/// Presentation header that binds a BBS eligibility proof to a specific
/// `(election_id, nullifier, signal)`. `signal` is the canonical encoding of the voter's chosen
/// option; folding it in makes the accepted ballot non-malleable. Both variable-length inputs
/// are length-prefixed so the encoding is unambiguous; `nullifier` is fixed-width and trails.
/// `H("phi-vote-bind-v2" || len(election_id) || election_id || len(signal) || signal || nullifier)`.
///
/// The domain string (`phi-vote-bind-v2`) and this byte layout are consensus-relevant and MUST stay
/// in sync with the on-chain `CastVote` caller (see `x/voting` in phi-chain), which passes the same
/// `signal` bytes it requires the message to carry.
pub fn bind_nonce(election_id: &[u8], nullifier: &[u8; NULLIFIER_LEN], signal: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"phi-vote-bind-v2");
    h.update((election_id.len() as u64).to_be_bytes());
    h.update(election_id);
    h.update((signal.len() as u64).to_be_bytes());
    h.update(signal);
    h.update(nullifier);
    h.finalize().into()
}

/// Verify a serialized BBS eligibility proof bound to `(election_id, nullifier, signal)`.
///
/// The proof must have been produced against the presentation header [`bind_nonce`]; verification
/// uses the issuer public key and that same header, so the proof is accepted only for the exact
/// nullifier *and chosen option* it was bound to (anti-replay + non-malleable ballot). Returns a
/// fail-safe bool (any error → `false`).
///
/// **Not Sybil-resistant on its own.** This checks eligibility and binds the proof to one
/// nullifier and one option, but it does *not* prove `nullifier = H(secret, election)` for a `secret`
/// that is a signed claim of the credential — so a holder can present the same credential under many
/// distinct nullifiers and vote more than once. One-credential-one-vote needs the ZK derivation proof
/// (a vetted Semaphore/arkworks circuit) tracked as the remaining step; until it lands, production
/// `CastVote` tallies must not treat this as a uniqueness guarantee.
pub fn verify_bound_proof(
    bbs_proof: &[u8],
    issuer_public_key: &[u8],
    election_id: &[u8],
    nullifier: &[u8; NULLIFIER_LEN],
    signal: &[u8],
) -> bool {
    let nonce = bind_nonce(election_id, nullifier, signal);
    crate::bbs::verify_proof_bytes(bbs_proof, issuer_public_key, &nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbs;

    #[test]
    fn external_nullifier_is_per_election() {
        assert_ne!(
            external_nullifier(b"election-1"),
            external_nullifier(b"election-2")
        );
        assert_eq!(external_nullifier(b"e"), external_nullifier(b"e"));
    }

    #[test]
    fn nullifier_is_deterministic_per_secret_and_election() {
        let a = nullifier(b"voter-secret", b"election-1");
        assert_eq!(a, nullifier(b"voter-secret", b"election-1"));
        // Same secret, different election → uncorrelated.
        assert_ne!(a, nullifier(b"voter-secret", b"election-2"));
        // Different secret, same election → different nullifier.
        assert_ne!(a, nullifier(b"other-secret", b"election-1"));
    }

    #[test]
    fn bind_nonce_changes_with_nullifier_election_and_signal() {
        let n1 = nullifier(b"s", b"e1");
        let n2 = nullifier(b"s", b"e2");
        assert_ne!(bind_nonce(b"e1", &n1, b"0"), bind_nonce(b"e1", &n2, b"0"));
        assert_ne!(bind_nonce(b"e1", &n1, b"0"), bind_nonce(b"e2", &n1, b"0"));
        // The chosen option (signal) is part of the header.
        assert_ne!(bind_nonce(b"e1", &n1, b"0"), bind_nonce(b"e1", &n1, b"1"));
        // Length-prefixing keeps the (election_id, signal) split unambiguous.
        assert_ne!(bind_nonce(b"ab", &n1, b"c"), bind_nonce(b"a", &n1, b"bc"));
    }

    #[test]
    fn bound_proof_roundtrip_and_replay_rejection() {
        // A credential whose claims include the voter secret (index 0).
        let claims = vec![b"voter_secret=deadbeef".to_vec(), b"region=north".to_vec()];
        let kp = bbs::generate_keypair(claims.len() as u32).unwrap();
        let sig = bbs::sign_credential(&claims, &kp.secret).unwrap();

        let election = b"election-42";
        let signal = b"option-2"; // the voter's chosen option
        let null = nullifier(b"voter_secret=deadbeef", election);
        let nonce = bind_nonce(election, &null, signal);

        // The holder presents an eligibility proof bound to this (nullifier, signal) (reveals region only).
        let proof = bbs::derive_proof(&claims, &sig, &[1], &nonce).unwrap();
        let proof_bytes = proof.to_bytes();

        // Accepted for the bound (election, nullifier, signal).
        assert!(verify_bound_proof(
            &proof_bytes,
            &kp.public,
            election,
            &null,
            signal
        ));

        // Rejected if replayed under a different nullifier (the binding nonce no longer matches).
        let other = nullifier(b"voter_secret=deadbeef", b"election-99");
        assert!(!verify_bound_proof(
            &proof_bytes,
            &kp.public,
            election,
            &other,
            signal
        ));
        // Rejected under a different election.
        assert!(!verify_bound_proof(
            &proof_bytes,
            &kp.public,
            b"election-99",
            &null,
            signal
        ));
    }

    #[test]
    fn ballot_signal_is_non_malleable() {
        // The same proof + nullifier re-tagged with a DIFFERENT signal (chosen option) must fail,
        // so a relay/aggregator cannot flip a voter's choice.
        let claims = vec![b"voter_secret=cafe".to_vec(), b"region=south".to_vec()];
        let kp = bbs::generate_keypair(claims.len() as u32).unwrap();
        let sig = bbs::sign_credential(&claims, &kp.secret).unwrap();

        let election = b"election-7";
        let null = nullifier(b"voter_secret=cafe", election);
        let chosen = b"yes";
        let nonce = bind_nonce(election, &null, chosen);
        let proof_bytes = bbs::derive_proof(&claims, &sig, &[1], &nonce)
            .unwrap()
            .to_bytes();

        // Accepted only for the exact option the voter bound.
        assert!(verify_bound_proof(
            &proof_bytes,
            &kp.public,
            election,
            &null,
            chosen
        ));
        // The same proof + same nullifier, but claiming a different option, is rejected.
        assert!(!verify_bound_proof(
            &proof_bytes,
            &kp.public,
            election,
            &null,
            b"no"
        ));
    }
}
