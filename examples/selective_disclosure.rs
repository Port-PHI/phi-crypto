// SPDX-License-Identifier: Apache-2.0
//! Selective disclosure with the phi-bbs-v1 suite: prove "over 18" without revealing the birth
//! year. Run with: `cargo run --example selective_disclosure`.

use phi_crypto::bbs;

fn main() {
    // Issuer signs a credential with four claims.
    let claims: Vec<Vec<u8>> = vec![
        b"did=did:phi:abc".to_vec(),
        b"birth_year=1990".to_vec(),
        b"city=metropolis".to_vec(),
        b"over_18=true".to_vec(),
    ];
    let issuer = bbs::generate_keypair(claims.len() as u32).expect("keygen");
    let signature = bbs::sign_credential(&claims, &issuer.secret).expect("sign");

    // Holder reveals only claim 3 ("over_18=true"), bound to a verifier nonce.
    let nonce = b"verifier-nonce-001";
    let proof = bbs::derive_proof(&claims, &signature, &[3], nonce).expect("derive");

    // Verifier checks the proof against the issuer public key and the same nonce.
    let ok = bbs::verify_proof(&proof, &issuer.public, nonce);
    println!("proof valid: {ok}");
    for (index, claim) in &proof.revealed {
        println!("revealed[{index}] = {}", String::from_utf8_lossy(claim));
    }
    assert!(ok, "the disclosure proof must verify");
}
