// SPDX-License-Identifier: Apache-2.0
//! Cross-check tests for the Flutter FFI surface.

use crate::api;
use phi_crypto::{bbs, did, seed, semaphore, voting, webauthn};

use base64::Engine;
use sha2::{Digest, Sha256};

const K1: u8 = 0; // secp256k1
const R1: u8 = 1; // secp256r1


fn sign_is_byte_identical_to_core(code: u8, curve: did::Curve) {
    let kp = did::generate_keypair(curve);
    let msg = b"phi ffi cross-check message";
    // ECDSA here is deterministic (RFC 6979), so the wrapper's output must be the exact same bytes.
    let via_api = api::sign(code, kp.secret.to_vec(), msg.to_vec()).expect("api sign");
    let via_core = did::sign(curve, &kp.secret, msg).expect("core sign");
    assert_eq!(
        via_api, via_core,
        "wrapper sign must equal core sign byte-for-byte"
    );
    assert_eq!(via_api.len(), 64, "raw r||s");
    assert!(api::verify_signature(
        code,
        kp.public.clone(),
        msg.to_vec(),
        via_api.clone()
    ));
    assert!(did::verify(curve, &kp.public, msg, &via_api));
    assert!(!api::verify_signature(
        code,
        kp.public.clone(),
        b"other".to_vec(),
        via_api
    ));
}

#[test]
fn sign_matches_core_secp256k1() {
    sign_is_byte_identical_to_core(K1, did::Curve::Secp256k1);
}

#[test]
fn sign_matches_core_secp256r1() {
    sign_is_byte_identical_to_core(R1, did::Curve::Secp256r1);
}

#[test]
fn generate_keypair_roundtrips_and_is_curve_gated() {
    for (code, curve) in [(K1, did::Curve::Secp256k1), (R1, did::Curve::Secp256r1)] {
        let kp = api::generate_keypair(code).expect("keypair");
        assert_eq!(kp.secret.len(), 32);
        assert!(!kp.public.is_empty());
        let msg = b"round trip";
        let sig = api::sign(code, kp.secret.clone(), msg.to_vec()).unwrap();
        assert!(did::verify(curve, &kp.public, msg, &sig));
    }
    assert!(api::generate_keypair(2).is_err());
    assert!(!api::verify_signature(
        2,
        vec![0u8; 33],
        vec![0u8; 1],
        vec![0u8; 64]
    ));
}

#[test]
fn did_from_public_matches_core() {
    for (code, curve) in [(K1, did::Curve::Secp256k1), (R1, did::Curve::Secp256r1)] {
        let kp = did::generate_keypair(curve);
        let via_api = api::did_from_public(code, kp.public.clone()).expect("api did");
        let via_core = did::did_from_public(curve, &kp.public).expect("core did");
        assert_eq!(via_api, via_core);
        assert!(via_api.starts_with("did:phi:"));
        assert_eq!(via_api.len(), "did:phi:".len() + 64);
    }
    // Invalid key → error (fail-closed, same as core).
    assert!(api::did_from_public(R1, vec![0u8; 10]).is_err());
}


/// The client round-trip the mobile onboarding actually performs: generate a phrase, derive the key, then use that key through the ORDINARY sign/verify/DID path.
#[test]
fn seed_derived_key_signs_and_verifies_through_the_normal_path() {
    let phrase = api::seed_generate_mnemonic();
    assert_eq!(phrase.split_whitespace().count(), 24);

    let kp = api::seed_derive_k1(phrase.clone(), String::new()).expect("derive");
    assert_eq!(kp.secret.len(), 32);
    assert_eq!(kp.public.len(), 33, "compressed SEC1 k1");

    let msg = b"phi seed-derived tx".to_vec();
    let sig = api::sign(K1, kp.secret.clone(), msg.clone()).expect("sign");
    assert!(api::verify_signature(
        K1,
        kp.public.clone(),
        msg,
        sig.clone()
    ));
    assert_eq!(sig.len(), 64);

    let via_api = api::did_from_public(K1, kp.public.clone()).expect("did");
    let via_core = did::did_from_public(did::Curve::Secp256k1, &kp.public).expect("core did");
    assert_eq!(via_api, via_core);
    assert!(via_api.starts_with("did:phi:"));
}

/// THE RECOVERY ROUND-TRIP, at the client boundary: the same phrase re-derives the identical key on a "new device", and the wrapper agrees with the core byte-for-byte (so a phone and a browser recover the same identity).
#[test]
fn seed_derivation_is_deterministic_and_matches_core() {
    let phrase = api::seed_generate_mnemonic();

    let device_one = api::seed_derive_k1(phrase.clone(), String::new()).expect("derive");
    let device_two = api::seed_derive_k1(phrase.clone(), String::new()).expect("re-derive");
    assert_eq!(
        device_one.secret, device_two.secret,
        "same phrase → same key"
    );
    assert_eq!(device_one.public, device_two.public);

    let via_core = seed::derive_k1_keypair(&phrase, "").expect("core derive");
    assert_eq!(device_one.secret, via_core.secret.to_vec());
    assert_eq!(device_one.public, via_core.public);

    // A passphrase is part of the secret, and a bad phrase is an error — not a silent other identity.
    let with_passphrase = api::seed_derive_k1(phrase, "extra".to_string()).expect("derive");
    assert_ne!(device_one.secret, with_passphrase.secret);
    assert!(api::seed_derive_k1("not a mnemonic".to_string(), String::new()).is_err());
}

// voting / semaphore — deterministic, must match the core byte-for-byte

#[test]
fn compute_nullifier_matches_core() {
    let (secret, topic) = (b"voter-secret".to_vec(), b"proposal-7".to_vec());
    let via_api = api::compute_nullifier(secret.clone(), topic.clone());
    let via_core = voting::compute_nullifier(&secret, &topic).to_vec();
    assert_eq!(via_api, via_core);
    assert_eq!(via_api.len(), voting::NULLIFIER_LEN);
}

#[test]
fn semaphore_nullifier_matches_core() {
    let (secret, election) = (b"voter-secret".to_vec(), b"election-42".to_vec());
    let via_api = api::semaphore_nullifier(secret.clone(), election.clone());
    let via_core = semaphore::nullifier(&secret, &election).to_vec();
    assert_eq!(via_api, via_core);
}

#[test]
fn semaphore_bind_nonce_matches_core_and_rejects_bad_length() {
    let election = b"election-42".to_vec();
    let signal = b"option-2".to_vec();
    let null = semaphore::nullifier(b"voter-secret", &election);
    let via_api = api::semaphore_bind_nonce(election.clone(), null.to_vec(), signal.clone());
    let via_core = semaphore::bind_nonce(&election, &null, &signal).to_vec();
    assert_eq!(via_api, via_core);
    assert!(api::semaphore_bind_nonce(election, vec![0u8; 31], signal).is_empty());
}


#[test]
fn bbs_wrapper_and_core_are_cross_compatible() {
    let claims: Vec<Vec<u8>> = vec![
        b"voter_secret=deadbeef".to_vec(),
        b"region=north".to_vec(),
        b"tier=gold".to_vec(),
    ];
    let kp = api::bbs_generate_keypair(claims.len() as u32).expect("bbs keypair");

    let sig = api::bbs_sign_credential(claims.clone(), kp.secret.clone()).expect("sign");
    let nonce = b"presentation-nonce".to_vec();
    let reveal: Vec<u32> = vec![1]; // reveal only "region"
    let proof = api::bbs_derive_proof(claims.clone(), sig.clone(), reveal.clone(), nonce.clone())
        .expect("derive");
    assert!(
        bbs::verify_proof_bytes(&proof, &kp.public, &nonce),
        "core verifies wrapper proof"
    );
    assert!(api::bbs_verify_proof(
        proof.clone(),
        kp.public.clone(),
        nonce.clone()
    ));

    let core_sig = bbs::sign_credential(&claims, &kp.secret).unwrap();
    let core_proof = bbs::derive_proof(&claims, &core_sig, &[1usize], &nonce)
        .unwrap()
        .to_bytes();
    assert!(api::bbs_verify_proof(
        core_proof,
        kp.public.clone(),
        nonce.clone()
    ));

    let other = bbs::generate_keypair(claims.len() as u32).unwrap();
    assert!(!api::bbs_verify_proof(
        proof.clone(),
        other.public.clone(),
        nonce.clone()
    ));
    assert!(!bbs::verify_proof_bytes(&proof, &other.public, &nonce));
}


struct Fixture {
    auth_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
    challenge: Vec<u8>,
    public_key: Vec<u8>,
    origin: String,
    rp_id: String,
}

fn build_webauthn(up: bool, challenge: &[u8]) -> Fixture {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    let origin = "https://phi.example".to_string();
    let rp_id = "phi.example".to_string();
    let sk = SigningKey::random(&mut rand_core::OsRng);
    let public_key = p256::ecdsa::VerifyingKey::from(&sk)
        .to_sec1_bytes()
        .to_vec();

    let client = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
        origin
    );
    let client_data_json = client.into_bytes();

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes())); // rpIdHash
    auth_data.push(if up { 0x01 } else { 0x00 }); // UP flag
    auth_data.extend_from_slice(&[0, 0, 0, 1]); // counter

    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    let sig: Signature = sk.sign(&signed);
    let sig = sig.normalize_s().unwrap_or(sig); // low-S (core rejects high-S)

    Fixture {
        auth_data,
        client_data_json,
        signature: sig.to_bytes().to_vec(),
        challenge: challenge.to_vec(),
        public_key,
        origin,
        rp_id,
    }
}

fn wrapper_result(f: &Fixture, require_uv: bool) -> bool {
    api::webauthn_verify(
        f.auth_data.clone(),
        f.client_data_json.clone(),
        f.signature.clone(),
        f.challenge.clone(),
        f.public_key.clone(),
        f.origin.clone(),
        f.rp_id.clone(),
        require_uv,
    )
}

fn core_result(f: &Fixture, require_uv: bool) -> bool {
    let assertion = webauthn::WebAuthnAssertion {
        authenticator_data: f.auth_data.clone(),
        client_data_json: f.client_data_json.clone(),
        signature: f.signature.clone(),
    };
    webauthn::verify_webauthn(
        &assertion,
        &f.challenge,
        &f.public_key,
        &f.origin,
        &f.rp_id,
        require_uv,
    )
}

#[test]
fn webauthn_verify_matches_core_on_both_branches() {
    let ok = build_webauthn(true, b"the-sign-doc-hash");
    assert!(wrapper_result(&ok, false));
    assert_eq!(wrapper_result(&ok, false), core_result(&ok, false));

    let mut bad = build_webauthn(true, b"the-sign-doc-hash");
    bad.challenge = b"a-different-challenge".to_vec();
    assert!(!wrapper_result(&bad, false));
    assert_eq!(wrapper_result(&bad, false), core_result(&bad, false));

    let no_up = build_webauthn(false, b"the-sign-doc-hash");
    assert!(!wrapper_result(&no_up, false));
    assert_eq!(wrapper_result(&no_up, false), core_result(&no_up, false));

    assert!(
        !wrapper_result(&ok, true),
        "require_uv rejects a UP-only assertion"
    );
    assert_eq!(wrapper_result(&ok, true), core_result(&ok, true));
}


#[test]
fn core_secret_is_zeroizing() {
    let kp = did::generate_keypair(did::Curve::Secp256r1);
    let _bind: &zeroize::Zeroizing<Vec<u8>> = &kp.secret;
    let bkp = bbs::generate_keypair(2).unwrap();
    let _bbind: &zeroize::Zeroizing<Vec<u8>> = &bkp.secret;
}

/// The claim material frb moves out of Dart is held as `Vec<Vec<u8>>`, and the wrappers wrap it in `Zeroizing`.
#[test]
fn zeroize_reaches_nested_claim_buffers() {
    use zeroize::Zeroize;

    let mut claims: Vec<Vec<u8>> = vec![
        b"name=alice".to_vec(),
        b"birth_year=1990".to_vec(),
        b"national_id=1234567891".to_vec(),
    ];
    assert!(
        claims.iter().any(|c| c.iter().any(|&b| b != 0)),
        "live claim material is not all-zero"
    );

    claims.zeroize();
    assert!(claims.is_empty(), "the outer Vec is cleared");

    let mut one = b"national_id=1234567891".to_vec();
    one.zeroize();
    assert!(
        one.iter().all(|&b| b == 0) && one.is_empty(),
        "a claim buffer is wiped, not merely dropped"
    );
}

/// Type-level pins for the secret-bearing wrapper arguments.
#[test]
fn secret_bearing_arguments_are_wrapped() {
    use zeroize::Zeroizing;

    let phrase: Zeroizing<String> = Zeroizing::new(seed::generate_mnemonic().to_string());
    let pass: Zeroizing<String> = Zeroizing::new(String::new());
    let kp = seed::derive_k1_keypair(&phrase, &pass).expect("derive");
    let _: &zeroize::Zeroizing<Vec<u8>> = &kp.secret;

    // Claim material and issuer secret, as `bbs_sign_credential` holds them.
    let claims: Zeroizing<Vec<Vec<u8>>> = Zeroizing::new(vec![b"over_18=true".to_vec()]);
    let issuer = bbs::generate_keypair(1).unwrap();
    let secret: Zeroizing<Vec<u8>> = Zeroizing::new(issuer.secret.to_vec());
    let sig = bbs::sign_credential(&claims, &secret).expect("sign");
    assert!(!sig.is_empty());
}


/// The `vote_prove` wrapper forwards to the core prover and its serialized proof verifies through the core verifier — the exact round-trip the WASM `voteProve` export performs.
#[cfg(feature = "voting_snark")]
#[test]
fn vote_prove_roundtrip_verifies() {
    let claims: Vec<Vec<u8>> = vec![
        b"voter_secret=9f2c1a7b4e6d8003".to_vec(), // index 0 (VOTER_SECRET_MSG_INDEX) — hidden
        b"region=north".to_vec(),
        b"cohort=2025".to_vec(),
    ];
    let kp = bbs::generate_keypair(claims.len() as u32).unwrap();
    let sig = bbs::sign_credential(&claims, &kp.secret).unwrap();
    let chain_id = b"flutter-chain-1".to_vec();
    let election_id = b"flutter-election-1".to_vec();
    let signal = 1u32.to_be_bytes().to_vec(); // canonical chosen-option encoding

    // Prove via the FFI wrapper; reveal index 1 only (never the voter secret at index 0).
    let proof = api::vote_prove(
        claims,
        sig,
        kp.public.clone(),
        vec![1],
        chain_id.clone(),
        election_id.clone(),
        signal.clone(),
    )
    .expect("vote_prove");

    assert!(phi_crypto::voting_snark::verify_vote(
        &proof,
        &kp.public,
        &chain_id,
        &election_id,
        &signal
    ));
    let other_signal = 2u32.to_be_bytes().to_vec();
    assert!(!phi_crypto::voting_snark::verify_vote(
        &proof,
        &kp.public,
        &chain_id,
        &election_id,
        &other_signal
    ));
    assert!(!phi_crypto::voting_snark::verify_vote(
        &proof,
        &kp.public,
        &chain_id,
        b"other-election",
        &signal
    ));
}
