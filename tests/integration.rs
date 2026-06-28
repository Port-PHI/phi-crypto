// SPDX-License-Identifier: Apache-2.0
//! Integration tests — the public phi-crypto API as seen by an external consumer.
//!
//! Two roles: (1) verify each domain's full flow from the public boundary, and (2) serve as
//! living documentation of the correct issue/present/verify pattern.
//!
//! In-module unit tests cover negative cases (bad input, high-S, ...); this file focuses on
//! end-to-end paths and known-answer test (KAT) vectors.

use hex_literal::hex;
use phi_crypto::{bbs, did, voting, webauthn};

// ---------------------------------------------------------------------------
// BBS+ — unlinkable selective disclosure (the project's signature feature)
// ---------------------------------------------------------------------------

/// Sample claims of an identity credential.
fn credential_claims() -> Vec<Vec<u8>> {
    vec![
        b"did=did:phi:abc".to_vec(), // 0
        b"birth_year=1990".to_vec(), // 1 — sensitive, must not be revealed
        b"city=metropolis".to_vec(), // 2
        b"over_18=true".to_vec(),    // 3 — the only revealed claim
    ]
}

#[test]
fn bbs_proves_over_18_without_revealing_birth_year() {
    let claims = credential_claims();
    // The issuer signs the credential.
    let issuer = bbs::generate_keypair(claims.len() as u32).expect("keygen");
    let signature = bbs::sign_credential(&claims, &issuer.secret).expect("sign");

    // The holder reveals only "over 18" (index 3).
    let nonce = b"verifier-session-nonce-001";
    let proof = bbs::derive_proof(&claims, &signature, &[3], nonce).expect("derive");

    // Exactly one claim is revealed, and it is over_18 — not birth year, name, or city.
    assert_eq!(proof.revealed.len(), 1);
    assert_eq!(proof.revealed[0], (3u32, b"over_18=true".to_vec()));
    assert!(
        !proof
            .revealed
            .iter()
            .any(|(_, c)| c.starts_with(b"birth_year")),
        "the birth year must never be revealed in the proof"
    );

    // The verifier accepts the proof against the issuer's public key.
    assert!(bbs::verify_proof(&proof, &issuer.public, nonce));
}

#[test]
fn bbs_serialized_boundary_roundtrip() {
    // The exact path crossing the C-ABI/WASM boundary: SelectiveProof → bytes → verify_proof_bytes.
    let claims = credential_claims();
    let issuer = bbs::generate_keypair(claims.len() as u32).expect("keygen");
    let signature = bbs::sign_credential(&claims, &issuer.secret).unwrap();
    let nonce = b"boundary-nonce";
    let proof = bbs::derive_proof(&claims, &signature, &[2, 3], nonce).unwrap();

    let bytes = proof.to_bytes();
    let decoded = bbs::SelectiveProof::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded.message_count, proof.message_count);
    assert_eq!(decoded.revealed, proof.revealed);

    // The same function that ffi::phi_bbs_verify_proof calls.
    assert!(bbs::verify_proof_bytes(&bytes, &issuer.public, nonce));
    // Malformed proof bytes must be rejected (safe default, no panic).
    assert!(!bbs::verify_proof_bytes(
        b"\x00\x01\x02",
        &issuer.public,
        nonce
    ));
}

#[test]
fn bbs_two_presentations_are_unlinkable() {
    // The project's signature property: two presentations from one credential with the same disclosure must not be linkable (identical).
    let claims = credential_claims();
    let issuer = bbs::generate_keypair(claims.len() as u32).expect("keygen");
    let signature = bbs::sign_credential(&claims, &issuer.secret).unwrap();

    let p1 = bbs::derive_proof(&claims, &signature, &[3], b"n").unwrap();
    let p2 = bbs::derive_proof(&claims, &signature, &[3], b"n").unwrap();
    assert_ne!(
        p1.proof, p2.proof,
        "two presentations must differ byte-for-byte (unlinkability)"
    );
    assert!(bbs::verify_proof(&p1, &issuer.public, b"n"));
    assert!(bbs::verify_proof(&p2, &issuer.public, b"n"));
}

// ---------------------------------------------------------------------------
// DID — dual-curve signing and identifier derivation
// ---------------------------------------------------------------------------

#[test]
fn did_dual_curve_sign_verify() {
    for curve in [did::Curve::Secp256k1, did::Curve::Secp256r1] {
        let kp = did::generate_keypair(curve);
        let msg = b"phi sign-doc";
        let sig = did::sign(curve, &kp.secret, msg).unwrap();
        assert_eq!(sig.len(), 64, "the raw r‖s signature must be 64 bytes");
        assert!(did::verify(curve, &kp.public, msg, &sig));
        // Curve separation: the same key/signature must not verify under the other curve.
        let other = if curve == did::Curve::Secp256k1 {
            did::Curve::Secp256r1
        } else {
            did::Curve::Secp256k1
        };
        assert!(
            !did::verify(other, &kp.public, msg, &sig),
            "a signature must not verify under the other curve"
        );
        // A valid key yields a full 32-byte DID.
        let did = did::did_from_public(curve, &kp.public).expect("valid key");
        assert!(did.starts_with("did:phi:"));
        assert_eq!(did.len(), "did:phi:".len() + 64);
    }
}

#[test]
fn did_derivation_fail_closed_and_kat() {
    // Fail-closed: the former raw-byte fallback is gone. pk = 0x02 ‖ 32×0xFF has
    // x ≥ the field modulus, so it is not a valid point and derivation returns an error instead of
    // fabricating an identifier.
    let mut bad = [0xFFu8; 33];
    bad[0] = 0x02;
    assert!(did::did_from_public(did::Curve::Secp256r1, &bad).is_err());

    // KAT for a valid key: the P-256 generator supplied in compressed SEC1 form (0x03 ‖ Gx).
    // canonical_sec1 re-emits it in the library's canonical (uncompressed, 0x04 ‖ Gx ‖ Gy) form, so
    // the DID is the full 32-byte SHA-256(tag=0x02 ‖ uncompressed), verified independently (Python).
    let generator_p256: [u8; 33] = [
        0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96,
    ];
    let did =
        did::did_from_public(did::Curve::Secp256r1, &generator_p256).expect("generator is valid");
    assert_eq!(
        did,
        "did:phi:c964dd3b1e45ae4d2c46bdf532b3880751cef7b89ec654af6a2cc82b2b026e76"
    );
}

// ---------------------------------------------------------------------------
// voting — nullifier and threshold tally
// ---------------------------------------------------------------------------

#[test]
fn nullifier_known_answer() {
    // KAT: sha256("phi-nullifier-v1" ‖ u64be(9) ‖ "phi-voter" ‖ u64be(11) ‖ "proposal-42").
    let got = voting::compute_nullifier(b"phi-voter", b"proposal-42");
    let want = hex!("01ce6dba7fc9b2d6f01aab4d2e370c068ef6dd75cc45a0592d53b6794ead14c7");
    assert_eq!(got, want);
}

#[test]
fn voting_double_vote_is_neutralized() {
    let topic = b"proposal-42";
    let alice = voting::VoteProof {
        nullifier: voting::compute_nullifier(b"alice", topic),
    };
    let bob = voting::VoteProof {
        nullifier: voting::compute_nullifier(b"bob", topic),
    };
    let alice_again = voting::VoteProof {
        nullifier: voting::compute_nullifier(b"alice", topic),
    };
    let votes = vec![alice, bob, alice_again];

    assert_eq!(
        voting::distinct_nullifiers(&votes),
        2,
        "alice's double vote is counted once"
    );
    assert!(voting::verify_threshold_tally(&votes, 2));
    assert!(!voting::verify_threshold_tally(&votes, 3));
}

// ---------------------------------------------------------------------------
// WebAuthn — consensus-critical path (the one phi-chain calls via C-ABI)
// ---------------------------------------------------------------------------

#[test]
fn webauthn_end_to_end_passkey_assertion() {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let origin = "https://portphi.com";
    let rp_id = "portphi.com";
    let challenge = b"phi-tx-sign-doc-hash-0001"; // typically the transaction/sign-doc hash

    // Build a P-256 passkey using the same DID API (simulates a Secure Enclave).
    let kp = did::generate_keypair(did::Curve::Secp256r1);

    // clientDataJSON exactly as produced by navigator.credentials.get.
    let client = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
        origin
    );
    let client_bytes = client.into_bytes();

    // authenticatorData = rpIdHash(32) ‖ flags(UP) ‖ counter(4).
    let mut auth = Vec::new();
    auth.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    auth.push(0x01); // User-Presence bit
    auth.extend_from_slice(&[0, 0, 0, 1]);

    // Signed envelope = authenticatorData ‖ SHA256(clientDataJSON).
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(&client_bytes));

    // Sign with the passkey key (low-S enforced automatically).
    let signature = did::sign(did::Curve::Secp256r1, &kp.secret, &signed).unwrap();

    let assertion = webauthn::WebAuthnAssertion {
        authenticator_data: auth,
        client_data_json: client_bytes,
        signature,
    };

    assert!(
        webauthn::verify_webauthn(&assertion, challenge, &kp.public, origin, rp_id),
        "a valid passkey assertion must be accepted"
    );
    // Wrong origin (anti-phishing) must be rejected.
    assert!(!webauthn::verify_webauthn(
        &assertion,
        challenge,
        &kp.public,
        "https://evil.example",
        rp_id
    ));
    // Wrong challenge (anti-replay) must be rejected.
    assert!(!webauthn::verify_webauthn(
        &assertion,
        b"other-challenge",
        &kp.public,
        origin,
        rp_id
    ));
}

// ---------------------------------------------------------------------------
// W3C bbs-2023 interoperability — official IETF/W3C known-answer vector
// ---------------------------------------------------------------------------

/// Byte-exact interop with the official `bbs-2023` (BLS12-381 SHA-256) test vectors. This inline
/// case (signature fixture 001 from the IETF/W3C suite) proves the `bbs_2023` module matches the
/// standard; the full fixture sweep lives in `tests/bbs_2023_kat.rs`. The `bbs_2023` module is
/// native-only, which is always satisfied for host-run integration tests.
#[test]
fn bbs_w3c_2023_interop_vector() {
    use phi_crypto::bbs_2023;

    let sk = hex!("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
    let pk = hex!(
        "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28"
        "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f"
        "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"
    );
    let header = hex!("11223344556677889900aabbccddeeff");
    let message = hex!("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02").to_vec();
    let expected_sig = hex!(
        "88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f3"
        "2fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c"
        "681bf061ce7e7f6091fe78c1cb8af103"
    );

    // Deterministic signing reproduces the official signature byte-for-byte.
    let messages = [message];
    let sig = bbs_2023::sign(&sk, &pk, &header, &messages).expect("sign");
    assert_eq!(
        sig,
        expected_sig.to_vec(),
        "must match the official bbs-2023 signature vector"
    );
    assert!(bbs_2023::verify(&pk, &header, &messages, &expected_sig));
}
