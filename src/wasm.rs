// SPDX-License-Identifier: Apache-2.0
//! WASM output — the browser boundary for the Phi web app/site.
//!
//! The phi-crypto core exposed to JavaScript. Callers pass `Uint8Array`
//! (Rust `&[u8]`/`Vec<u8>`) and strings as `string`. Verification functions
//! return `bool`; fallible functions return `Result`, surfaced as JS exceptions.
//!
//! Web usage (after `wasm-pack build --target web`):
//! ```js
//! import init, { bbsDeriveProof, bbsVerifyProof } from "./pkg-web/phi_crypto.js";
//! await init();
//! const proof = bbsDeriveProof(claims, signature, Uint32Array.of(3), nonce);
//! const ok = bbsVerifyProof(proof, issuerPublicKey, nonce);
//! ```
//!
//! > The WASM output must be loaded with **SRI** on the site (project security rule).

// This `allow` is only for the generated wasm-bindgen glue; no hand-written unsafe here.
#![allow(unsafe_code)]

use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::{bbs, did, voting, webauthn};

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

// ===========================================================================
// DID — dual-curve signing
// ===========================================================================

/// DID key pair for JS consumers (both fields as `Uint8Array`). The Rust-side secret is wiped on
/// drop; the `Vec` returned by the `secret` getter is a copy owned by JS and is its to manage.
#[wasm_bindgen]
#[derive(zeroize::ZeroizeOnDrop)]
pub struct WasmKeyPair {
    secret: Vec<u8>,
    #[zeroize(skip)]
    public: Vec<u8>,
}

#[wasm_bindgen]
impl WasmKeyPair {
    /// Raw secret key (32 bytes). Sensitive — store securely in the browser.
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
        secret: kp.secret.to_vec(),
        public: kp.public,
    })
}

/// Signs a message (raw 64-byte `r ‖ s` output with enforced low-S).
#[wasm_bindgen(js_name = sign)]
pub fn sign(curve_code: u8, secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
    let curve = curve_from_code(curve_code)?;
    did::sign(curve, secret, msg).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verifies an ECDSA signature (high-S rejected). `true` = valid.
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

// ===========================================================================
// WebAuthn — passkey assertion verification (P-256)
// ===========================================================================

/// Verifies a WebAuthn assertion over `authenticatorData ‖ SHA256(clientDataJSON)`.
/// `true` = valid; any failure returns `false`.
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
) -> bool {
    let assertion = webauthn::WebAuthnAssertion {
        authenticator_data: auth_data.to_vec(),
        client_data_json: client_data_json.to_vec(),
        signature: signature.to_vec(),
    };
    webauthn::verify_webauthn(&assertion, challenge, public_key, origin, rp_id)
}

// ===========================================================================
// voting — nullifier
// ===========================================================================

/// Computes the nullifier of a secret for a topic (32 bytes).
#[wasm_bindgen(js_name = computeNullifier)]
pub fn compute_nullifier(secret: &[u8], topic: &[u8]) -> Vec<u8> {
    voting::compute_nullifier(secret, topic).to_vec()
}

// ===========================================================================
// semaphore — per-election nullifier binding (web vote client)
// ===========================================================================

/// The voter's per-election nullifier: `compute_nullifier(secret, external_nullifier(election_id))`
/// (32 bytes). Deterministic per (secret, election); uncorrelated across elections.
#[wasm_bindgen(js_name = semaphoreNullifier)]
pub fn semaphore_nullifier(secret: &[u8], election_id: &[u8]) -> Vec<u8> {
    crate::semaphore::nullifier(secret, election_id).to_vec()
}

/// The BBS presentation header that binds an eligibility proof to `(election_id, nullifier, signal)`
/// (32 bytes). `signal` is the canonical encoding of the voter's chosen option; folding it into the
/// header makes the accepted ballot non-malleable and matches the on-chain verifier
/// (`phi_semaphore_verify_vote` / `VerifySemaphoreVote`) byte-for-byte. The web vote client derives its
/// proof against this nonce, so the proof verifies on-chain for exactly this nullifier *and* this chosen
/// option. `nullifier` must be 32 bytes; returns an empty vec on a bad length.
#[wasm_bindgen(js_name = semaphoreBindNonce)]
pub fn semaphore_bind_nonce(election_id: &[u8], nullifier: &[u8], signal: &[u8]) -> Vec<u8> {
    match <[u8; voting::NULLIFIER_LEN]>::try_from(nullifier) {
        Ok(n) => crate::semaphore::bind_nonce(election_id, &n, signal).to_vec(),
        Err(_) => Vec::new(),
    }
}

// ===========================================================================
// BBS+ — unlinkable selective disclosure
// ===========================================================================

/// BBS+ issuer key pair for JS consumers. The Rust-side secret is wiped on drop; the `Vec`
/// returned by the `secret` getter is a copy owned by JS and is its to manage.
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
        secret: kp.secret.to_vec(),
        public: kp.public,
    })
}

/// Signs a credential (an `Array` of `Uint8Array`, one per claim). Returns the serialized signature.
#[wasm_bindgen(js_name = bbsSignCredential)]
pub fn bbs_sign_credential(claims: Array, secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    let claims = claims_from_array(&claims)?;
    bbs::sign_credential(&claims, secret).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Builds a selective proof revealing only the `reveal` indices. Returns the serialized
/// proof (the bytes accepted by [`bbs_verify_proof`]).
#[wasm_bindgen(js_name = bbsDeriveProof)]
pub fn bbs_derive_proof(
    claims: Array,
    signature: &[u8],
    reveal: Vec<u32>,
    nonce: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let claims = claims_from_array(&claims)?;
    let reveal: Vec<usize> = reveal.iter().map(|&i| i as usize).collect();
    let proof = bbs::derive_proof(&claims, signature, &reveal, nonce)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(proof.to_bytes())
}

/// Verifies a serialized selective proof against the issuer public key and `nonce`.
/// `true` = valid.
#[wasm_bindgen(js_name = bbsVerifyProof)]
pub fn bbs_verify_proof(proof: &[u8], public_key: &[u8], nonce: &[u8]) -> bool {
    bbs::verify_proof_bytes(proof, public_key, nonce)
}
