// SPDX-License-Identifier: Apache-2.0
//! Flutter FFI surface — the native boundary for the Phi mobile app.

use phi_crypto::secret::into_boundary_owned;
use phi_crypto::{bbs, did, seed, semaphore, voting, webauthn};
use zeroize::Zeroizing;

/// Maps a curve code to the core type: `0` = secp256k1, `1` = secp256r1.
fn curve_from_code(code: u8) -> Result<did::Curve, String> {
    match code {
        0 => Ok(did::Curve::Secp256k1),
        1 => Ok(did::Curve::Secp256r1),
        _ => Err("curve code must be 0 (secp256k1) or 1 (secp256r1)".to_string()),
    }
}


/// A DID key pair for Dart consumers.
pub struct PhiKeyPair {
    /// Raw secret key (32 bytes).
    pub secret: Vec<u8>,
    /// SEC1 public key, as emitted by the core for the curve.
    pub public: Vec<u8>,
}

/// Generates a DID key pair on the requested curve (0=k1, 1=r1).
pub fn generate_keypair(curve: u8) -> Result<PhiKeyPair, String> {
    let curve = curve_from_code(curve)?;
    let kp = did::generate_keypair(curve);
    Ok(PhiKeyPair {
        secret: into_boundary_owned(kp.secret),
        public: kp.public,
    })
}

/// Signs a message (raw 64-byte `r ‖ s` output with enforced low-S).
pub fn sign(curve: u8, secret: Vec<u8>, msg: Vec<u8>) -> Result<Vec<u8>, String> {
    let secret = Zeroizing::new(secret);
    let curve = curve_from_code(curve)?;
    did::sign(curve, &secret, &msg).map_err(|e| e.to_string())
}

/// Verifies an ECDSA signature (high-S rejected).
pub fn verify_signature(curve: u8, public_key: Vec<u8>, msg: Vec<u8>, sig: Vec<u8>) -> bool {
    match curve_from_code(curve) {
        Ok(curve) => did::verify(curve, &public_key, &msg, &sig),
        Err(_) => false,
    }
}

/// Derives a `did:phi:…` identifier from a public key.
pub fn did_from_public(curve: u8, public_key: Vec<u8>) -> Result<String, String> {
    let curve = curve_from_code(curve)?;
    did::did_from_public(curve, &public_key).map_err(|e| e.to_string())
}


/// Generates a 24-word BIP-39 recovery phrase.
pub fn seed_generate_mnemonic() -> String {
    into_boundary_owned(seed::generate_mnemonic())
}

/// Derives the self-custody k1 key pair from a recovery phrase, at the pinned Phi derivation path.
pub fn seed_derive_k1(mnemonic: String, passphrase: String) -> Result<PhiKeyPair, String> {
    let mnemonic = Zeroizing::new(mnemonic);
    let passphrase = Zeroizing::new(passphrase);
    let kp = seed::derive_k1_keypair(&mnemonic, &passphrase).map_err(|e| e.to_string())?;
    Ok(PhiKeyPair {
        secret: into_boundary_owned(kp.secret),
        public: kp.public,
    })
}


/// Verifies a WebAuthn assertion over `authenticatorData ‖ SHA256(clientDataJSON)`.
#[allow(clippy::too_many_arguments)]
pub fn webauthn_verify(
    auth_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
    challenge: Vec<u8>,
    public_key: Vec<u8>,
    origin: String,
    rp_id: String,
    require_uv: bool,
) -> bool {
    let assertion = webauthn::WebAuthnAssertion {
        authenticator_data: auth_data,
        client_data_json,
        signature,
    };
    webauthn::verify_webauthn(
        &assertion,
        &challenge,
        &public_key,
        &origin,
        &rp_id,
        require_uv,
    )
}


/// Computes the nullifier of a secret for a topic (32 bytes).
pub fn compute_nullifier(secret: Vec<u8>, topic: Vec<u8>) -> Vec<u8> {
    let secret = Zeroizing::new(secret);
    voting::compute_nullifier(&secret, &topic).to_vec()
}


/// The voter's per-election nullifier (32 bytes).
pub fn semaphore_nullifier(secret: Vec<u8>, election_id: Vec<u8>) -> Vec<u8> {
    let secret = Zeroizing::new(secret);
    semaphore::nullifier(&secret, &election_id).to_vec()
}

/// The BBS presentation header binding an eligibility proof to `(election_id, nullifier, signal)` (32 bytes).
pub fn semaphore_bind_nonce(election_id: Vec<u8>, nullifier: Vec<u8>, signal: Vec<u8>) -> Vec<u8> {
    match <[u8; voting::NULLIFIER_LEN]>::try_from(nullifier.as_slice()) {
        Ok(n) => semaphore::bind_nonce(&election_id, &n, &signal).to_vec(),
        Err(_) => Vec::new(),
    }
}

// BBS+ — unlinkable selective disclosure (holder surface)

/// A BBS+ issuer key pair for Dart consumers.
pub struct PhiBbsKeyPair {
    /// Issuer secret key (serialized).
    pub secret: Vec<u8>,
    /// Issuer public key (serialized).
    pub public: Vec<u8>,
}

/// Generates an issuer key pair for a credential with `message_count` claims.
pub fn bbs_generate_keypair(message_count: u32) -> Result<PhiBbsKeyPair, String> {
    let kp = bbs::generate_keypair(message_count).map_err(|e| e.to_string())?;
    Ok(PhiBbsKeyPair {
        secret: into_boundary_owned(kp.secret),
        public: kp.public,
    })
}

/// Signs a credential (one entry per claim).
pub fn bbs_sign_credential(claims: Vec<Vec<u8>>, secret: Vec<u8>) -> Result<Vec<u8>, String> {
    let claims = Zeroizing::new(claims);
    let secret = Zeroizing::new(secret);
    bbs::sign_credential(&claims, &secret).map_err(|e| e.to_string())
}

/// Builds a selective proof revealing only the `reveal` indices.
pub fn bbs_derive_proof(
    claims: Vec<Vec<u8>>,
    signature: Vec<u8>,
    reveal: Vec<u32>,
    nonce: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let claims = Zeroizing::new(claims);
    let signature = Zeroizing::new(signature);
    let reveal: Vec<usize> = reveal.iter().map(|&i| i as usize).collect();
    let proof =
        bbs::derive_proof(&claims, &signature, &reveal, &nonce).map_err(|e| e.to_string())?;
    Ok(proof.to_bytes())
}

/// Verifies a serialized selective proof against the issuer public key and `nonce`.
pub fn bbs_verify_proof(proof: Vec<u8>, public_key: Vec<u8>, nonce: Vec<u8>) -> bool {
    bbs::verify_proof_bytes(&proof, &public_key, &nonce)
}


/// Produce a composed anonymous-vote proof on the voter's device — the STEP-1 prover.
#[cfg(feature = "voting_snark")]
pub fn vote_prove(
    claims: Vec<Vec<u8>>,
    signature: Vec<u8>,
    issuer_public_key: Vec<u8>,
    reveal: Vec<u32>,
    election_id: Vec<u8>,
    signal: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let claims = zeroize::Zeroizing::new(claims);
    let reveal: Vec<usize> = reveal.iter().map(|&i| i as usize).collect();
    phi_crypto::voting_snark::prove_vote_bytes(
        claims.as_slice(),
        &signature,
        &issuer_public_key,
        &reveal,
        &election_id,
        &signal,
    )
    .map_err(|e| e.to_string())
}
