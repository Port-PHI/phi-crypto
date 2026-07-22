// SPDX-License-Identifier: Apache-2.0
//! WebAuthn verifier (P-256).

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

/// The clientDataJSON fields this verifier reads.
#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
    /// Absent on same-origin assertions; `true` when the ceremony ran inside a cross-origin frame.
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
    /// Present only when the ceremony was cross-origin, naming the embedding page.
    #[serde(rename = "topOrigin", default)]
    top_origin: Option<String>,
}

/// User-Presence bit within the authenticatorData flags byte.
const FLAG_USER_PRESENT: u8 = 0x01;
/// User-Verification bit within the authenticatorData flags byte.
const FLAG_USER_VERIFIED: u8 = 0x04;
/// Backup-Eligible bit: the credential may be synced off this authenticator.
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
/// Backup-State bit: the credential currently IS backed up (synced to a cloud keychain).
const FLAG_BACKUP_STATE: u8 = 0x10;

/// What an accepted assertion carried, beyond the fact that it verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssertionDetails {
    /// authenticatorData signature counter.
    pub sign_count: u32,
    /// User-Presence flag (always true for an accepted assertion — presence is mandatory).
    pub user_present: bool,
    /// User-Verification flag: a biometric or PIN gesture was completed.
    pub user_verified: bool,
    /// Backup-Eligible flag: this credential may be synced beyond the authenticator that made it.
    pub backup_eligible: bool,
    /// Backup-State flag: this credential is currently backed up.
    pub backup_state: bool,
}

/// Verify a WebAuthn assertion.
pub fn verify_webauthn(
    assertion: &WebAuthnAssertion,
    expected_challenge: &[u8],
    public_key: &[u8],
    expected_origin: &str,
    expected_rp_id: &str,
    require_uv: bool,
) -> bool {
    verify_webauthn_details(
        assertion,
        expected_challenge,
        public_key,
        expected_origin,
        expected_rp_id,
        require_uv,
    )
    .is_some()
}

/// Verify an assertion and, when it is valid, return what it carried.
pub fn verify_webauthn_details(
    assertion: &WebAuthnAssertion,
    expected_challenge: &[u8],
    public_key: &[u8],
    expected_origin: &str,
    expected_rp_id: &str,
    require_uv: bool,
) -> Option<AssertionDetails> {
    if verify_inner(
        assertion,
        expected_challenge,
        public_key,
        expected_origin,
        expected_rp_id,
        require_uv,
    ) {
        let flags = assertion.authenticator_data[32];
        let sign_count = u32::from_be_bytes(
            assertion.authenticator_data[33..37]
                .try_into()
                .expect("authenticatorData length was validated"),
        );
        return Some(AssertionDetails {
            sign_count,
            user_present: flags & FLAG_USER_PRESENT != 0,
            user_verified: flags & FLAG_USER_VERIFIED != 0,
            backup_eligible: flags & FLAG_BACKUP_ELIGIBLE != 0,
            backup_state: flags & FLAG_BACKUP_STATE != 0,
        });
    }
    None
}

fn verify_inner(
    assertion: &WebAuthnAssertion,
    expected_challenge: &[u8],
    public_key: &[u8],
    expected_origin: &str,
    expected_rp_id: &str,
    require_uv: bool,
) -> bool {
    let Ok(cd) = serde_json::from_slice::<ClientData>(&assertion.client_data_json) else {
        return false;
    };
    if cd
        .typ
        .as_bytes()
        .ct_eq("webauthn.get".as_bytes())
        .unwrap_u8()
        != 1
    {
        return false;
    }
    if cd
        .origin
        .as_bytes()
        .ct_eq(expected_origin.as_bytes())
        .unwrap_u8()
        != 1
    {
        return false;
    }
    if cd.cross_origin == Some(true) || cd.top_origin.is_some() {
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
        return false; // user presence always required
    }
    if require_uv && flags & FLAG_USER_VERIFIED == 0 {
        return false; // sensitive operation: a verifying gesture (biometric/PIN) is mandatory
    }

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

    struct Built {
        assertion: WebAuthnAssertion,
        challenge: Vec<u8>,
        pk: Vec<u8>,
        origin: String,
        rp_id: String,
    }

    fn build(up: bool, high_s: bool, origin: &str, rp_id: &str, challenge: &[u8]) -> Built {
        build_flags(up, false, high_s, origin, rp_id, challenge)
    }

    fn build_flags(
        up: bool,
        uv: bool,
        high_s: bool,
        origin: &str,
        rp_id: &str,
        challenge: &[u8],
    ) -> Built {
        build_full(up, uv, high_s, origin, rp_id, challenge, None, 1, 0)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_full(
        up: bool,
        uv: bool,
        high_s: bool,
        origin: &str,
        rp_id: &str,
        challenge: &[u8],
        provenance: Option<&str>,
        sign_count: u32,
        extra_flags: u8,
    ) -> Built {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let pk = p256::ecdsa::VerifyingKey::from(&sk)
            .to_sec1_bytes()
            .to_vec();

        let client = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}",{}}}"#,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
            origin,
            provenance.unwrap_or(r#""crossOrigin":false"#)
        );
        let client_bytes = client.into_bytes();

        let mut auth = Vec::new();
        auth.extend_from_slice(&Sha256::digest(rp_id.as_bytes())); // rpIdHash
        let mut flags = 0u8;
        if up {
            flags |= FLAG_USER_PRESENT;
        }
        if uv {
            flags |= FLAG_USER_VERIFIED;
        }
        flags |= extra_flags;
        auth.push(flags);
        auth.extend_from_slice(&sign_count.to_be_bytes()); // counter

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

    /// An assertion produced inside a cross-origin frame must be refused.
    #[test]
    fn rejects_cross_origin_assertion() {
        let ch = b"cross-origin-challenge";
        for provenance in [
            r#""crossOrigin":true"#,
            r#""crossOrigin":true,"topOrigin":"https://evil.example""#,
        ] {
            let b = build_full(
                true,
                false,
                false,
                "https://portphi.com",
                "portphi.com",
                ch,
                Some(provenance),
                1,
                0,
            );
            assert!(
                !verify_webauthn(
                    &b.assertion,
                    &b.challenge,
                    &b.pk,
                    &b.origin,
                    &b.rp_id,
                    false
                ),
                "an assertion from a cross-origin frame must be rejected ({provenance})"
            );
        }
    }

    /// A top-level origin is only ever set for a cross-origin ceremony, so its presence is refused rather than interpreted — even when crossOrigin itself claims false.
    #[test]
    fn rejects_top_origin_even_when_cross_origin_claims_false() {
        let ch = b"top-origin-challenge";
        let b = build_full(
            true,
            false,
            false,
            "https://portphi.com",
            "portphi.com",
            ch,
            Some(r#""crossOrigin":false,"topOrigin":"https://evil.example""#),
            1,
            0,
        );
        assert!(
            !verify_webauthn(
                &b.assertion,
                &b.challenge,
                &b.pk,
                &b.origin,
                &b.rp_id,
                false
            ),
            "a top-level origin must not appear on an assertion this verifier accepts"
        );
    }

    /// Same-origin assertions are unaffected, whether they state crossOrigin false or omit it.
    #[test]
    fn accepts_same_origin_assertion_with_or_without_the_field() {
        let ch = b"same-origin-challenge";
        for provenance in [r#""crossOrigin":false"#, r#""extra":1"#] {
            let b = build_full(
                true,
                false,
                false,
                "https://portphi.com",
                "portphi.com",
                ch,
                Some(provenance),
                1,
                0,
            );
            assert!(
                verify_webauthn(
                    &b.assertion,
                    &b.challenge,
                    &b.pk,
                    &b.origin,
                    &b.rp_id,
                    false
                ),
                "a same-origin assertion must still verify ({provenance})"
            );
        }
    }

    /// The counter and backup flags are surfaced to callers that ask for them.
    #[test]
    fn surfaces_sign_count_and_backup_flags() {
        let ch = b"details-challenge";
        let b = build_full(
            true,
            true,
            false,
            "https://portphi.com",
            "portphi.com",
            ch,
            None,
            42,
            FLAG_BACKUP_ELIGIBLE | FLAG_BACKUP_STATE,
        );

        let details =
            verify_webauthn_details(&b.assertion, &b.challenge, &b.pk, &b.origin, &b.rp_id, true)
                .expect("a valid assertion must verify");
        assert_eq!(details.sign_count, 42);
        assert!(details.user_present);
        assert!(details.user_verified);
        assert!(details.backup_eligible);
        assert!(details.backup_state);

        let plain = build_full(
            true,
            false,
            false,
            "https://portphi.com",
            "portphi.com",
            ch,
            None,
            0,
            0,
        );
        let details = verify_webauthn_details(
            &plain.assertion,
            &plain.challenge,
            &plain.pk,
            &plain.origin,
            &plain.rp_id,
            false,
        )
        .expect("a valid assertion must verify");
        assert_eq!(details.sign_count, 0);
        assert!(!details.user_verified);
        assert!(!details.backup_eligible);
        assert!(!details.backup_state);
    }

    /// The detail-returning entry point is the same verifier: a rejected assertion yields nothing, exactly as the boolean form returns false.
    #[test]
    fn details_and_bool_agree_on_rejection() {
        let ch = b"agreement-challenge";
        let b = build_full(
            true,
            false,
            false,
            "https://portphi.com",
            "portphi.com",
            ch,
            Some(r#""crossOrigin":true"#),
            1,
            0,
        );
        assert!(!verify_webauthn(
            &b.assertion,
            &b.challenge,
            &b.pk,
            &b.origin,
            &b.rp_id,
            false
        ));
        assert!(
            verify_webauthn_details(
                &b.assertion,
                &b.challenge,
                &b.pk,
                &b.origin,
                &b.rp_id,
                false
            )
            .is_none(),
            "both entry points must agree that this is rejected"
        );
    }

    // Builds an equivalent high-S signature from a low-S one (s' = n - s).
    fn high_s_variant(sig: &Signature) -> Signature {
        use p256::elliptic_curve::scalar::IsHigh;
        let (r, s) = (sig.r(), sig.s());
        let neg_s = -*s;
        let candidate = Signature::from_scalars(r, neg_s).unwrap();
        if bool::from(candidate.s().is_high()) {
            candidate
        } else {
            *sig
        }
    }

    fn verify(b: &Built) -> bool {
        verify_uv(b, false)
    }

    fn verify_uv(b: &Built, require_uv: bool) -> bool {
        verify_webauthn(
            &b.assertion,
            &b.challenge,
            &b.pk,
            &b.origin,
            &b.rp_id,
            require_uv,
        )
    }

    #[test]
    fn uv_flag_gates_sensitive_operations() {
        let with_uv = build_flags(
            true,
            true,
            false,
            "https://portphi.com",
            "portphi.com",
            b"challenge-uv",
        );
        assert!(
            verify_uv(&with_uv, true),
            "UV set must pass require_uv=true"
        );
        assert!(
            verify_uv(&with_uv, false),
            "UV set must also pass require_uv=false"
        );

        let up_only = build_flags(
            true,
            false,
            false,
            "https://portphi.com",
            "portphi.com",
            b"challenge-uv",
        );
        assert!(
            !verify_uv(&up_only, true),
            "a UP-only assertion must be REJECTED when UV is required"
        );
        assert!(
            verify_uv(&up_only, false),
            "a UP-only assertion is fine for a non-sensitive operation"
        );
    }

    #[test]
    fn user_presence_is_always_required() {
        for require_uv in [false, true] {
            let no_up = build_flags(
                false,
                true,
                false,
                "https://portphi.com",
                "portphi.com",
                b"c",
            );
            assert!(
                !verify_uv(&no_up, require_uv),
                "missing UP must be rejected regardless of require_uv={require_uv}"
            );
        }
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
            &b.rp_id,
            false
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
            &b.rp_id,
            false
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
