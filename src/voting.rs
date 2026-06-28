// SPDX-License-Identifier: Apache-2.0
//! Anonymous voting primitives.
//!
//! - [`compute_nullifier`] — a deterministic per-voter, per-topic tag that reveals
//!   double-voting without leaking identity and is unlinkable across topics (as long
//!   as the secret stays private).
//! - [`verify_threshold_tally`] — counts distinct nullifiers and checks the threshold.
//!
//! Zero-knowledge eligibility proof (membership of an active DID owner) comes from
//! [`crate::bbs`]; this module provides only the nullifier and tally primitives
//! (Semaphore/MACI/World ID pattern).

use std::collections::HashSet;

use sha2::{Digest, Sha256};

/// Nullifier length in bytes.
pub const NULLIFIER_LEN: usize = 32;

/// Deterministic nullifier of a secret for a topic. Two votes from the same secret on
/// the same topic yield identical nullifiers (double-vote detection); different topics
/// yield uncorrelated nullifiers.
pub fn compute_nullifier(secret: &[u8], topic: &[u8]) -> [u8; NULLIFIER_LEN] {
    let mut h = Sha256::new();
    h.update(b"phi-nullifier-v1"); // domain separation
    h.update((secret.len() as u64).to_be_bytes());
    h.update(secret);
    h.update((topic.len() as u64).to_be_bytes());
    h.update(topic);
    h.finalize().into()
}

/// A recorded vote (nullifier tag; the choice/eligibility proof is verified separately).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteProof {
    /// The voter's unique nullifier for this topic.
    pub nullifier: [u8; NULLIFIER_LEN],
}

/// Counts distinct nullifiers (duplicate votes are counted once).
pub fn distinct_nullifiers(votes: &[VoteProof]) -> usize {
    let mut seen: HashSet<[u8; NULLIFIER_LEN]> = HashSet::with_capacity(votes.len());
    for v in votes {
        seen.insert(v.nullifier);
    }
    seen.len()
}

/// Whether the count of distinct voters reaches the threshold (double-votes are ignored).
pub fn verify_threshold_tally(votes: &[VoteProof], threshold: u64) -> bool {
    distinct_nullifiers(votes) as u64 >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullifier_is_deterministic() {
        let n1 = compute_nullifier(b"secret", b"proposal-7");
        let n2 = compute_nullifier(b"secret", b"proposal-7");
        assert_eq!(n1, n2);
    }

    #[test]
    fn nullifier_differs_by_topic_and_secret() {
        let base = compute_nullifier(b"secret", b"proposal-7");
        assert_ne!(base, compute_nullifier(b"secret", b"proposal-8"));
        assert_ne!(base, compute_nullifier(b"other-secret", b"proposal-7"));
    }

    #[test]
    fn length_prefix_prevents_ambiguity() {
        // Without length prefixes, ("ab","c") and ("a","bc") would collide; here they must differ.
        assert_ne!(
            compute_nullifier(b"ab", b"c"),
            compute_nullifier(b"a", b"bc")
        );
    }

    #[test]
    fn threshold_counts_distinct_voters() {
        let a = VoteProof {
            nullifier: compute_nullifier(b"alice", b"t"),
        };
        let b = VoteProof {
            nullifier: compute_nullifier(b"bob", b"t"),
        };
        let a_dup = VoteProof {
            nullifier: compute_nullifier(b"alice", b"t"),
        }; // alice double-vote
        let votes = vec![a.clone(), b.clone(), a_dup];
        assert_eq!(
            distinct_nullifiers(&votes),
            2,
            "a double vote is counted once"
        );
        assert!(verify_threshold_tally(&votes, 2));
        assert!(!verify_threshold_tally(&votes, 3));
    }
}
