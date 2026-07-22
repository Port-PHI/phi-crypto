// SPDX-License-Identifier: Apache-2.0
//! Selective disclosure with the phi-bbs-v1 suite: prove "over 18" without revealing the birth year.

use phi_crypto::bbs;

fn main() {
    let claims: Vec<Vec<u8>> = vec![
        b"did=did:phi:abc".to_vec(),
        b"birth_year=1990".to_vec(),
        b"city=metropolis".to_vec(),
        b"over_18=true".to_vec(),
    ];
    let issuer = bbs::generate_keypair(claims.len() as u32).expect("keygen");
    let signature = bbs::sign_credential(&claims, &issuer.secret).expect("sign");

    let nonce = b"verifier-nonce-001";
    let proof = bbs::derive_proof(&claims, &signature, &[3], nonce).expect("derive");

    let ok = bbs::verify_proof(&proof, &issuer.public, nonce);
    println!("proof valid: {ok}");
    for (index, claim) in &proof.revealed {
        println!("revealed[{index}] = {}", String::from_utf8_lossy(claim));
    }
    assert!(ok, "the disclosure proof must verify");
}
