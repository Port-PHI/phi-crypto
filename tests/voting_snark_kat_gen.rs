// SPDX-License-Identifier: Apache-2.0
//! Deterministic-input generator for the phi-chain `voting_snark` KAT fixture.
#![cfg(feature = "voting_snark")]

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use phi_crypto::bbs;
use phi_crypto::voting_snark::prove_vote;

#[test]
fn generate_voting_snark_kat() {
    let chain_id: &[u8] = b"phi-snark-testnet";
    let election_id: &[u8] = b"snark-election-1";
    let option_index: u32 = 1; // the voter commits to option index 1
    let signal = option_index.to_be_bytes(); // must equal phi-chain voteSignal(option_index)

    let claims = vec![
        b"voter_secret=9f2c1a7b4e6d8003c5a1f0e2d4b6980a".to_vec(), // index 0 — HIDDEN, never committed
        b"region=north".to_vec(),                                  // index 1 — revealed (public)
        b"cohort=2025".to_vec(), // index 2 — hidden but not the secret
    ];
    let reveal = [1usize];

    let kp = bbs::generate_keypair(claims.len() as u32).expect("keypair");
    let sig = bbs::sign_credential(&claims, &kp.secret).expect("sign");
    let proof = prove_vote(
        &claims,
        &sig,
        &kp.public,
        &reveal,
        chain_id,
        election_id,
        &signal,
    )
    .expect("prove_vote");

    let nullifier = proof.nullifier_bytes().expect("nullifier bytes");
    assert_eq!(
        nullifier.len(),
        48,
        "nullifier must be a 48-byte compressed G1 point"
    );
    let proof_bytes = proof.to_bytes().expect("proof bytes");

    assert!(
        !contains(&proof_bytes, b"voter_secret="),
        "voter secret must never appear in the committed proof blob",
    );

    let json = format!(
        "{{\n  \"_comment\": \"phi-chain voting_snark KAT — public/ZK data only; see phi-crypto/tests/voting_snark_kat_gen.rs\",\n  \"chain_id\": \"{}\",\n  \"election_id\": \"{}\",\n  \"option_index\": {},\n  \"signal_hex\": \"{}\",\n  \"issuer_bbs_pubkey_b64\": \"{}\",\n  \"nullifier_b64\": \"{}\",\n  \"proof_b64\": \"{}\"\n}}",
        std::str::from_utf8(chain_id).unwrap(),
        std::str::from_utf8(election_id).unwrap(),
        option_index,
        hex::encode(signal),
        STANDARD.encode(&kp.public),
        STANDARD.encode(nullifier),
        STANDARD.encode(&proof_bytes),
    );

    println!("BEGIN_KAT_JSON");
    println!("{json}");
    println!("END_KAT_JSON");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
