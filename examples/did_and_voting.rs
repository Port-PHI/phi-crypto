// SPDX-License-Identifier: Apache-2.0
//! Dual-curve DID signatures and a double-vote-resistant nullifier.
//! Run with: `cargo run --example did_and_voting`.

use phi_crypto::{did, voting};

fn main() {
    // Dual-curve DID: sign and verify on both secp256k1 and secp256r1.
    for curve in [did::Curve::Secp256k1, did::Curve::Secp256r1] {
        let label = match curve {
            did::Curve::Secp256k1 => "secp256k1",
            did::Curve::Secp256r1 => "secp256r1",
        };
        let kp = did::generate_keypair(curve);
        let msg = b"phi sign-doc";
        let sig = did::sign(curve, &kp.secret, msg).expect("sign");
        let ok = did::verify(curve, &kp.public, msg, &sig);
        let id = did::did_from_public(curve, &kp.public).expect("valid key");
        println!("{label}: verify={ok}, did={id}");
        assert!(ok, "signature must verify");
    }

    // Voting nullifier: the same voter on the same topic counts once.
    let topic = b"proposal-42";
    let votes = vec![
        voting::VoteProof {
            nullifier: voting::compute_nullifier(b"alice", topic),
        },
        voting::VoteProof {
            nullifier: voting::compute_nullifier(b"bob", topic),
        },
        voting::VoteProof {
            nullifier: voting::compute_nullifier(b"alice", topic),
        }, // duplicate
    ];
    let distinct = voting::distinct_nullifiers(&votes);
    println!("distinct voters: {distinct}");
    assert_eq!(distinct, 2, "the duplicate vote must collapse to one");
}
