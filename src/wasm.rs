// SPDX-License-Identifier: Apache-2.0
//! WASM output — the browser boundary for the Phi web app/site.

#![allow(unsafe_code)]

use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::secret::into_boundary_owned;
use crate::{bbs, did, seed, voting, webauthn};

/// Maps a curve code to the internal type: `0` = secp256k1, `1` = secp256r1.
fn curve_from_code(code: u8) -> Result<did::Curve, JsValue> {
    match code {
        0 => Ok(did::Curve::Secp256k1),
        1 => Ok(did::Curve::Secp256r1),
        _ => Err(JsValue::from_str(
            "curve code must be 0 (secp256k1) or 1 (secp256r1)",
        )),
    }
}

/// Converts an `Array` of `Uint8Array` claims into `Vec<Vec<u8>>`.
fn claims_from_array(claims: &Array) -> Result<Vec<Vec<u8>>, JsValue> {
    let mut out = Vec::with_capacity(claims.length() as usize);
    for v in claims.iter() {
        let arr = v
            .dyn_into::<Uint8Array>()
            .map_err(|_| JsValue::from_str("each claim must be a Uint8Array"))?;
        out.push(arr.to_vec());
    }
    Ok(out)
}

/// DID key pair for JS consumers (both fields as `Uint8Array`).
#[wasm_bindgen]
#[derive(zeroize::ZeroizeOnDrop)]
pub struct WasmKeyPair {
    secret: Vec<u8>,
    #[zeroize(skip)]
    public: Vec<u8>,
}

#[wasm_bindgen]
impl WasmKeyPair {
    /// Raw secret key (32 bytes).
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.secret.clone()
    }
    /// Compressed SEC1 public key (33 bytes).
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> Vec<u8> {
        self.public.clone()
    }
}

/// Generates a DID key pair on the requested curve (0=k1, 1=r1).
#[wasm_bindgen(js_name = generateKeypair)]
pub fn generate_keypair(curve_code: u8) -> Result<WasmKeyPair, JsValue> {
    let curve = curve_from_code(curve_code)?;
    let kp = did::generate_keypair(curve);
    Ok(WasmKeyPair {
        secret: into_boundary_owned(kp.secret),
        public: kp.public,
    })
}

/// Signs a message (raw 64-byte `r ‖ s` output with enforced low-S).
#[wasm_bindgen(js_name = sign)]
pub fn sign(curve_code: u8, secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
    let curve = curve_from_code(curve_code)?;
    did::sign(curve, secret, msg).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verifies an ECDSA signature (high-S rejected).
#[wasm_bindgen(js_name = verifySignature)]
pub fn verify_signature(curve_code: u8, public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match curve_from_code(curve_code) {
        Ok(curve) => did::verify(curve, public_key, msg, sig),
        Err(_) => false,
    }
}

/// Derives a `did:phi:…` identifier from a public key.
#[wasm_bindgen(js_name = didFromPublic)]
pub fn did_from_public(curve_code: u8, public_key: &[u8]) -> Result<String, JsValue> {
    let curve = curve_from_code(curve_code)?;
    did::did_from_public(curve, public_key).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generates a 24-word BIP-39 recovery phrase.
#[wasm_bindgen(js_name = seedGenerateMnemonic)]
pub fn seed_generate_mnemonic() -> String {
    into_boundary_owned(seed::generate_mnemonic())
}

/// Derives the self-custody k1 key pair from a recovery phrase, at the pinned Phi derivation path.
#[wasm_bindgen(js_name = seedDeriveK1)]
pub fn seed_derive_k1(mnemonic: &str, passphrase: &str) -> Result<WasmKeyPair, JsValue> {
    let kp = seed::derive_k1_keypair(mnemonic, passphrase)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(WasmKeyPair {
        secret: into_boundary_owned(kp.secret),
        public: kp.public,
    })
}

/// Verifies a WebAuthn assertion over `authenticatorData ‖ SHA256(clientDataJSON)`.
#[wasm_bindgen(js_name = webauthnVerify)]
#[allow(clippy::too_many_arguments)]
pub fn webauthn_verify(
    auth_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
    challenge: &[u8],
    public_key: &[u8],
    origin: &str,
    rp_id: &str,
    require_uv: bool,
) -> bool {
    let assertion = webauthn::WebAuthnAssertion {
        authenticator_data: auth_data.to_vec(),
        client_data_json: client_data_json.to_vec(),
        signature: signature.to_vec(),
    };
    webauthn::verify_webauthn(&assertion, challenge, public_key, origin, rp_id, require_uv)
}

/// Computes the nullifier of a secret for a topic (32 bytes).
#[wasm_bindgen(js_name = computeNullifier)]
pub fn compute_nullifier(secret: &[u8], topic: &[u8]) -> Vec<u8> {
    voting::compute_nullifier(secret, topic).to_vec()
}

/// The voter's per-election nullifier: `compute_nullifier(secret, external_nullifier(election_id))` (32 bytes).
#[wasm_bindgen(js_name = semaphoreNullifier)]
pub fn semaphore_nullifier(secret: &[u8], election_id: &[u8]) -> Vec<u8> {
    crate::semaphore::nullifier(secret, election_id).to_vec()
}

/// The BBS presentation header that binds an eligibility proof to `(election_id, nullifier, signal)` (32 bytes).
#[wasm_bindgen(js_name = semaphoreBindNonce)]
pub fn semaphore_bind_nonce(election_id: &[u8], nullifier: &[u8], signal: &[u8]) -> Vec<u8> {
    match <[u8; voting::NULLIFIER_LEN]>::try_from(nullifier) {
        Ok(n) => crate::semaphore::bind_nonce(election_id, &n, signal).to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Produce a composed anonymous-vote proof on the voter's device — the STEP-1 prover (`prove_vote`).
#[cfg(all(target_arch = "wasm32", feature = "voting_snark"))]
#[wasm_bindgen(js_name = voteProve)]
pub fn vote_prove(
    claims: Array,
    signature: &[u8],
    issuer_public_key: &[u8],
    reveal: Vec<u32>,
    chain_id: &[u8],
    election_id: &[u8],
    signal: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let claims = zeroize::Zeroizing::new(claims_from_array(&claims)?);
    let reveal: Vec<usize> = reveal.iter().map(|&i| i as usize).collect();
    crate::voting_snark::prove_vote_bytes(
        claims.as_slice(),
        signature,
        issuer_public_key,
        &reveal,
        chain_id,
        election_id,
        signal,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

// BBS+ — unlinkable selective disclosure

/// BBS+ issuer key pair for JS consumers.
#[wasm_bindgen]
#[derive(zeroize::ZeroizeOnDrop)]
pub struct WasmBbsKeyPair {
    secret: Vec<u8>,
    #[zeroize(skip)]
    public: Vec<u8>,
}

#[wasm_bindgen]
impl WasmBbsKeyPair {
    /// Issuer secret key (serialized).
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.secret.clone()
    }
    /// Issuer public key (serialized).
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> Vec<u8> {
        self.public.clone()
    }
}

/// Generates an issuer key pair for a credential with `message_count` claims.
#[wasm_bindgen(js_name = bbsGenerateKeypair)]
pub fn bbs_generate_keypair(message_count: u32) -> Result<WasmBbsKeyPair, JsValue> {
    let kp = bbs::generate_keypair(message_count).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(WasmBbsKeyPair {
        secret: into_boundary_owned(kp.secret),
        public: kp.public,
    })
}

/// Signs a credential (an `Array` of `Uint8Array`, one per claim).
#[wasm_bindgen(js_name = bbsSignCredential)]
pub fn bbs_sign_credential(claims: Array, secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    let claims = zeroize::Zeroizing::new(claims_from_array(&claims)?);
    bbs::sign_credential(&claims, secret).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Builds a selective proof revealing only the `reveal` indices.
#[wasm_bindgen(js_name = bbsDeriveProof)]
pub fn bbs_derive_proof(
    claims: Array,
    signature: &[u8],
    reveal: Vec<u32>,
    nonce: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let claims = zeroize::Zeroizing::new(claims_from_array(&claims)?);
    let reveal: Vec<usize> = reveal.iter().map(|&i| i as usize).collect();
    let proof = bbs::derive_proof(&claims, signature, &reveal, nonce)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(proof.to_bytes())
}

/// Verifies a serialized selective proof against the issuer public key and `nonce`.
#[wasm_bindgen(js_name = bbsVerifyProof)]
pub fn bbs_verify_proof(proof: &[u8], public_key: &[u8], nonce: &[u8]) -> bool {
    bbs::verify_proof_bytes(proof, public_key, nonce)
}
