// SPDX-License-Identifier: Apache-2.0
//! WebAuthn verifier (P-256).
//!
//! Called by phi-chain (via the C-ABI) to verify passkey signatures on-chain —
//! consensus-critical. The signature is checked over `authenticatorData ‖
//! SHA256(clientDataJSON)`, not over raw sign-bytes. All checks are mandatory:
//! - `type == "webauthn.get"`
//! - `challenge == base64url(expected_challenge)` (no padding)
//! - `origin == expected_origin`
//! - `rpIdHash == SHA256(expected_rp_id)`
//! - User-Presence (UP) flag set
//! - low-S enforced (signature malleability defense)

use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// A WebAuthn assertion (output of `navigator.credentials.get`).
pub struct WebAuthnAssertion {
    /// Raw authenticatorData.
    pub authenticator_data: Vec<u8>,
    /// Raw clientDataJSON (the exact signed bytes).
    pub client_data_json: Vec<u8>,
    /// ECDSA signature (DER or raw 64-byte `r ‖ s`).
    pub signature: Vec<u8>,
}

/// Only the required clientDataJSON fields; extras (crossOrigin, tokenBinding) are ignored.
#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
}

/// User-Presence bit within the authenticatorData flags byte.
const FLAG_USER_PRESENT: u8 = 0x01;

/// Verify a WebAuthn assertion. Returns `false` on any failure (never panics — consensus boundary).
///
/// - `expected_challenge`: expected challenge (raw bytes; the sign-doc/transaction hash).
/// - `public_key`: P-256 public key as SEC1 (compressed or uncompressed).
/// - `expected_origin`/`expected_rp_id`: allowed domain (phishing/replay defense).
pub fn verify_webauthn(
    assertion: &WebAuthnAssertion,
    expected_challenge: &[u8],
    public_key: &[u8],
    expected_origin: &str,
    expected_rp_id: &str,
) -> bool {
    // 1) Strictly parse clientDataJSON.
    let Ok(cd) = serde_json::from_slice::<ClientData>(&assertion.client_data_json) else {
        return false;
    };
    if cd.typ != "webauthn.get" {
        return false;
    }
    if cd.origin != expected_origin {
        return false;
    }
    // challenge must equal base64url (no padding) of expected_challenge.
    let want_challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected_challenge);
    if cd
        .challenge
        .as_bytes()
        .ct_eq(want_challenge.as_bytes())
        .unwrap_u8()
        != 1
    {
        return false;
    }

    // 2) authenticatorData: rpIdHash + flags.
    if assertion.authenticator_data.len() < 37 {
        return false; // 32 bytes rpIdHash + 1 flags + 4 counter
    }
    let rp_id_hash = &assertion.authenticator_data[..32];
    let want_rp_hash = Sha256::digest(expected_rp_id.as_bytes());
    if rp_id_hash.ct_eq(want_rp_hash.as_ref()).unwrap_u8() != 1 {
        return false;
    }
    let flags = assertion.authenticator_data[32];
    if flags & FLAG_USER_PRESENT == 0 {
        return false; // user presence required
    }

    // 3) Signed envelope = authenticatorData ‖ SHA256(clientDataJSON).
    let client_data_hash = Sha256::digest(&assertion.client_data_json);
    let mut signed = Vec::with_capacity(assertion.authenticator_data.len() + 32);
    signed.extend_from_slice(&assertion.authenticator_data);
    signed.extend_from_slice(&client_data_hash);

    // 4) Verify the P-256 signature with low-S enforced.
    verify_p256_low_s(public_key, &signed, &assertion.signature)
}

/// Verify ECDSA P-256 over a message (internal SHA-256 hash), rejecting high-S.
fn verify_p256_low_s(public_key: &[u8], signed: &[u8], sig_bytes: &[u8]) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let Ok(vk) = VerifyingKey::from_sec1_bytes(public_key) else {
        return false;
    };
    // Accept the signature as DER or raw 64 bytes.
    let signature = match Signature::from_der(sig_bytes) {
        Ok(s) => s,
        Err(_) => match Signature::from_slice(sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        },
    };
    if signature.normalize_s().is_some() {
        return false; // high-S → reject (malleability defense)
    }
    vk.verify(signed, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    // Builds a valid test assertion (authenticator simulation).
    struct Built {
        assertion: WebAuthnAssertion,
        challenge: Vec<u8>,
        pk: Vec<u8>,
        origin: String,
        rp_id: String,
    }

    fn build(up: bool, high_s: bool, origin: &str, rp_id: &str, challenge: &[u8]) -> Built {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let pk = p256::ecdsa::VerifyingKey::from(&sk)
            .to_sec1_bytes()
            .to_vec();

        let client = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
            origin
        );
        let client_bytes = client.into_bytes();

        let mut auth = Vec::new();
        auth.extend_from_slice(&Sha256::digest(rp_id.as_bytes())); // rpIdHash
        auth.push(if up { FLAG_USER_PRESENT } else { 0 }); // flags
        auth.extend_from_slice(&[0, 0, 0, 1]); // counter

        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&client_bytes));

        let sig: Signature = sk.sign(&signed);
        let low = sig.normalize_s().unwrap_or(sig); // ensure low-S (P-256 does not normalize automatically)
        let sig = if high_s {
            high_s_variant(&low) // for the high-S rejection test
        } else {
            low
        };

        Built {
            assertion: WebAuthnAssertion {
                authenticator_data: auth,
                client_data_json: client_bytes,
                signature: sig.to_der().as_bytes().to_vec(),
            },
            challenge: challenge.to_vec(),
            pk,
            origin: origin.to_string(),
            rp_id: rp_id.to_string(),
        }
    }

    // Builds an equivalent high-S signature from a low-S one (s' = n - s).
    fn high_s_variant(sig: &Signature) -> Signature {
        use p256::elliptic_curve::scalar::IsHigh;
        let (r, s) = (sig.r(), sig.s());
        let neg_s = -*s;
        let candidate = Signature::from_scalars(r, neg_s).unwrap();
        // Make sure this variant is high-S.
        if bool::from(candidate.s().is_high()) {
            candidate
        } else {
            *sig
        }
    }

    fn verify(b: &Built) -> bool {
        verify_webauthn(&b.assertion, &b.challenge, &b.pk, &b.origin, &b.rp_id)
    }

    #[test]
    fn accepts_valid_assertion() {
        let b = build(
            true,
            false,
            "https://portphi.com",
            "portphi.com",
            b"challenge-bytes-123",
        );
        assert!(verify(&b));
    }

    #[test]
    fn rejects_wrong_challenge() {
        let b = build(
            true,
            false,
            "https://portphi.com",
            "portphi.com",
            b"challenge-bytes-123",
        );
        assert!(!verify_webauthn(
            &b.assertion,
            b"WRONG",
            &b.pk,
            &b.origin,
            &b.rp_id
        ));
    }

    #[test]
    fn rejects_wrong_origin() {
        let b = build(true, false, "https://evil.example", "portphi.com", b"c");
        assert!(!verify_webauthn(
            &b.assertion,
            &b.challenge,
            &b.pk,
            "https://portphi.com",
            &b.rp_id
        ));
    }

    #[test]
    fn rejects_missing_user_presence() {
        let b = build(false, false, "https://portphi.com", "portphi.com", b"c");
        assert!(!verify(&b));
    }

    #[test]
    fn rejects_high_s() {
        let b = build(true, true, "https://portphi.com", "portphi.com", b"c");
        assert!(!verify(&b), "a high-S signature must be rejected");
    }

    #[test]
    fn rejects_wrong_type() {
        let mut b = build(true, false, "https://portphi.com", "portphi.com", b"c");
        // Change type to webauthn.create (must be rejected).
        let bad = String::from_utf8(b.assertion.client_data_json.clone())
            .unwrap()
            .replace("webauthn.get", "webauthn.create");
        b.assertion.client_data_json = bad.into_bytes();
        assert!(!verify(&b));
    }
}
