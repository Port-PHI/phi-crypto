// SPDX-License-Identifier: Apache-2.0
//! Semaphore-style nullifier binding for anonymous one-human-one-vote.

use sha2::{Digest, Sha256};

use crate::voting::{compute_nullifier, NULLIFIER_LEN};

/// External nullifier (the per-election domain): `H("phi-extnull-v1" || len(election_id) || election_id)`.
pub fn external_nullifier(election_id: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"phi-extnull-v1");
    h.update((election_id.len() as u64).to_be_bytes());
    h.update(election_id);
    h.finalize().into()
}

/// The voter's nullifier for an election: `compute_nullifier(secret, external_nullifier(election_id))`.
pub fn nullifier(secret: &[u8], election_id: &[u8]) -> [u8; NULLIFIER_LEN] {
    compute_nullifier(secret, &external_nullifier(election_id))
}

/// Presentation header that binds a BBS eligibility proof to a specific `(election_id, nullifier, signal)`.
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
        assert_ne!(bind_nonce(b"e1", &n1, b"0"), bind_nonce(b"e1", &n1, b"1"));
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

        let proof = bbs::derive_proof(&claims, &sig, &[1], &nonce).unwrap();
        let proof_bytes = proof.to_bytes();

        assert!(verify_bound_proof(
            &proof_bytes,
            &kp.public,
            election,
            &null,
            signal
        ));

        let other = nullifier(b"voter_secret=deadbeef", b"election-99");
        assert!(!verify_bound_proof(
            &proof_bytes,
            &kp.public,
            election,
            &other,
            signal
        ));
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

        assert!(verify_bound_proof(
            &proof_bytes,
            &kp.public,
            election,
            &null,
            chosen
        ));
        assert!(!verify_bound_proof(
            &proof_bytes,
            &kp.public,
            election,
            &null,
            b"no"
        ));
    }
}
