// SPDX-License-Identifier: Apache-2.0
//! C-ABI boundary for non-Rust consumers — primarily phi-chain (Go/cgo).

#![allow(unsafe_code)]

use core::slice;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::{bbs, did, voting, webauthn};

/// Runs an export body, converting a caught panic into the fail-closed return value.
fn guard<T>(fail_closed: T, body: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(fail_closed)
}

/// Convert pointer+length into a slice; `None` if the pointer is null with non-zero length.
/// # Safety
/// The caller MUST guarantee that, whenever `len > 0`, `ptr` points to a single allocated object of at least `len` readable bytes that stays valid and immutable for the entire call.
unsafe fn as_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(slice::from_raw_parts(ptr, len))
}

/// Same as [`as_slice`] but returns the result as a `&str` (UTF-8).
/// # Safety
/// Same as [`as_slice`].
unsafe fn as_str<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    core::str::from_utf8(as_slice(ptr, len)?).ok()
}

/// Curve code mapping: `0` = secp256k1, `1` = secp256r1.
fn curve_from_code(code: u8) -> Option<did::Curve> {
    match code {
        0 => Some(did::Curve::Secp256k1),
        1 => Some(did::Curve::Secp256r1),
        _ => None,
    }
}

/// Verify an ECDSA signature (k1/r1).
/// # Safety
/// All pointer+length pairs must reference valid readable regions.
#[no_mangle]
pub unsafe extern "C" fn phi_verify_signature(
    curve_code: u8,
    public_key: *const u8,
    public_key_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    guard(0, || {
        let (Some(curve), Some(pk), Some(m), Some(s)) = (
            curve_from_code(curve_code),
            as_slice(public_key, public_key_len),
            as_slice(msg, msg_len),
            as_slice(sig, sig_len),
        ) else {
            return 0;
        };
        did::verify(curve, pk, m, s) as i32
    })
}

/// Verify a WebAuthn assertion (P-256).
/// # Safety
/// All pointer+length pairs must reference valid readable regions; `origin`/`rp_id` must be UTF-8.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn phi_webauthn_verify(
    auth_data: *const u8,
    auth_data_len: usize,
    client_data_json: *const u8,
    client_data_json_len: usize,
    signature: *const u8,
    signature_len: usize,
    challenge: *const u8,
    challenge_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    origin: *const u8,
    origin_len: usize,
    rp_id: *const u8,
    rp_id_len: usize,
    require_uv: i32,
) -> i32 {
    guard(0, || {
        let (Some(ad), Some(cdj), Some(s), Some(ch), Some(pk), Some(org), Some(rp)) = (
            as_slice(auth_data, auth_data_len),
            as_slice(client_data_json, client_data_json_len),
            as_slice(signature, signature_len),
            as_slice(challenge, challenge_len),
            as_slice(public_key, public_key_len),
            as_str(origin, origin_len),
            as_str(rp_id, rp_id_len),
        ) else {
            return 0;
        };
        let assertion = webauthn::WebAuthnAssertion {
            authenticator_data: ad.to_vec(),
            client_data_json: cdj.to_vec(),
            signature: s.to_vec(),
        };
        webauthn::verify_webauthn(&assertion, ch, pk, org, rp, require_uv != 0) as i32
    })
}

/// Verify a BBS+ selective-disclosure proof (proof as serialized bytes).
/// # Safety
/// All pointer+length pairs must reference valid readable regions.
#[no_mangle]
pub unsafe extern "C" fn phi_bbs_verify_proof(
    proof: *const u8,
    proof_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
) -> i32 {
    guard(0, || {
        let (Some(p), Some(pk), Some(n)) = (
            as_slice(proof, proof_len),
            as_slice(public_key, public_key_len),
            as_slice(nonce, nonce_len),
        ) else {
            return 0;
        };
        bbs::verify_proof_bytes(p, pk, n) as i32
    })
}

/// Decode a length-prefixed list of revealed messages for bbs-2023 proof verification.
#[cfg(not(target_arch = "wasm32"))]
fn decode_revealed(b: &[u8]) -> Option<Vec<(usize, Vec<u8>)>> {
    fn u32_at(b: &[u8], pos: &mut usize) -> Option<u32> {
        let end = pos.checked_add(4)?;
        let bytes = b.get(*pos..end)?;
        *pos = end;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }
    let mut pos = 0usize;
    let count = u32_at(b, &mut pos)?;
    if count > crate::bbs::MAX_BBS_MESSAGES {
        return None;
    }
    let mut out: Vec<(usize, Vec<u8>)> = Vec::with_capacity(count as usize);
    let mut prev: Option<usize> = None;
    for _ in 0..count {
        let index = u32_at(b, &mut pos)? as usize;
        if let Some(p) = prev {
            if index <= p {
                return None; // unsorted or repeated
            }
        }
        prev = Some(index);

        let len = u32_at(b, &mut pos)? as usize;
        let end = pos.checked_add(len)?;
        let value = b.get(pos..end)?.to_vec();
        out.push((index, value));
        pos = end;
    }
    if pos != b.len() {
        return None; // trailing bytes
    }
    Some(out)
}

/// Verify a W3C `bbs-2023` (BLS12-381 SHA-256) selective-disclosure proof.
/// # Safety
/// All pointer+length pairs must reference valid readable regions for the duration of the call.
#[cfg(not(target_arch = "wasm32"))]
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn phi_bbs2023_verify_proof(
    proof: *const u8,
    proof_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    header: *const u8,
    header_len: usize,
    presentation_header: *const u8,
    presentation_header_len: usize,
    revealed: *const u8,
    revealed_len: usize,
) -> i32 {
    guard(0, || {
        let (Some(p), Some(pk), Some(h), Some(ph), Some(rev)) = (
            as_slice(proof, proof_len),
            as_slice(public_key, public_key_len),
            as_slice(header, header_len),
            as_slice(presentation_header, presentation_header_len),
            as_slice(revealed, revealed_len),
        ) else {
            return 0;
        };
        let Some(revealed_msgs) = decode_revealed(rev) else {
            return 0;
        };
        crate::bbs_2023::proof_verify(pk, h, ph, p, &revealed_msgs) as i32
    })
}

/// Compute a nullifier; writes 32 bytes into `out` (caller-allocated, `out_len` bytes of capacity).
/// # Safety
/// `out` must point to a writable buffer of at least `out_len` bytes, and `out_len` must state that buffer's true capacity: it is the length the write is bounds-checked against, so understating it only fails closed and overstating it is the caller's out-of-bounds bug to avoid.
#[no_mangle]
pub unsafe extern "C" fn phi_compute_nullifier(
    secret: *const u8,
    secret_len: usize,
    topic: *const u8,
    topic_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guard(0, || {
        if out.is_null() || out_len < voting::NULLIFIER_LEN {
            return 0;
        }
        let (Some(sec), Some(top)) = (as_slice(secret, secret_len), as_slice(topic, topic_len))
        else {
            return 0;
        };
        let n = voting::compute_nullifier(sec, top);
        let out_slice = slice::from_raw_parts_mut(out, voting::NULLIFIER_LEN);
        out_slice.copy_from_slice(&n);
        1
    })
}

/// Verify a BBS eligibility proof bound to `(election_id, nullifier, signal)` (Semaphore binding layer).
/// # Safety
/// All pointers must reference readable regions of the stated lengths; `nullifier` must be 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn phi_semaphore_verify_vote(
    bbs_proof: *const u8,
    bbs_proof_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    election_id: *const u8,
    election_id_len: usize,
    nullifier: *const u8,
    nullifier_len: usize,
    signal: *const u8,
    signal_len: usize,
) -> i32 {
    guard(0, || {
        let (Some(proof), Some(pk), Some(election), Some(sig)) = (
            as_slice(bbs_proof, bbs_proof_len),
            as_slice(public_key, public_key_len),
            as_slice(election_id, election_id_len),
            as_slice(signal, signal_len),
        ) else {
            return 0;
        };
        let Some(null) = as_slice(nullifier, nullifier_len) else {
            return 0;
        };
        let null_arr: [u8; crate::voting::NULLIFIER_LEN] = match null.try_into() {
            Ok(a) => a,
            Err(_) => return 0, // nullifier must be exactly 32 bytes
        };
        crate::semaphore::verify_bound_proof(proof, pk, election, &null_arr, sig) as i32
    })
}

/// Verify a composed anonymous-vote proof (STEP-1 `voting_snark`): BBS+ eligibility, the algebraic derivation `N = Hₑ^{m₀}`, the witness-equality that binds `m₀` to the credential's signed voter-secret message, and the `(chain_id, election_id, N, signal)` ballot binding — all in one shot.
/// # Safety
/// All pointer+length pairs must reference readable regions of the stated lengths for the whole call; `nullifier` must be [`NULLIFIER_POINT_LEN`](crate::voting_snark::NULLIFIER_POINT_LEN) (48) bytes.
#[cfg(feature = "voting_snark")]
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn phi_voting_verify_vote_v1(
    proof: *const u8,
    proof_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    chain_id: *const u8,
    chain_id_len: usize,
    election_id: *const u8,
    election_id_len: usize,
    nullifier: *const u8,
    nullifier_len: usize,
    signal: *const u8,
    signal_len: usize,
) -> i32 {
    guard(0, || {
        let (Some(proof_bytes), Some(pk), Some(chain), Some(election), Some(sig)) = (
            as_slice(proof, proof_len),
            as_slice(public_key, public_key_len),
            as_slice(chain_id, chain_id_len),
            as_slice(election_id, election_id_len),
            as_slice(signal, signal_len),
        ) else {
            return 0;
        };
        let Some(null) = as_slice(nullifier, nullifier_len) else {
            return 0;
        };
        let null_arr: [u8; crate::voting_snark::NULLIFIER_POINT_LEN] = match null.try_into() {
            Ok(a) => a,
            Err(_) => return 0, // nullifier must be exactly 48 bytes
        };
        let vote_proof = match crate::voting_snark::VoteProof::from_bytes(proof_bytes) {
            Ok(p) => p,
            Err(_) => return 0, // malformed / truncated / trailing bytes / bad nullifier point
        };
        let embedded = match vote_proof.nullifier_bytes() {
            Ok(n) => n,
            Err(_) => return 0,
        };
        if null_arr != embedded {
            return 0; // supplied dedup key is not the proof's bound nullifier
        }
        crate::voting_snark::verify_vote_proof(&vote_proof, pk, chain, election, sig) as i32
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a canonical revealed encoding from (index, value) pairs.
    #[cfg(not(target_arch = "wasm32"))]
    fn encode_revealed(entries: &[(u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (i, v) in entries {
            out.extend_from_slice(&i.to_be_bytes());
            out.extend_from_slice(&(v.len() as u32).to_be_bytes());
            out.extend_from_slice(v);
        }
        out
    }

    /// A canonical encoding decodes to exactly its entries and nothing else.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn decode_revealed_accepts_the_canonical_encoding() {
        let bytes = encode_revealed(&[(0, b"a"), (2, b"bb"), (7, b"")]);
        let got = decode_revealed(&bytes).expect("canonical input must decode");
        assert_eq!(
            got,
            vec![
                (0usize, b"a".to_vec()),
                (2usize, b"bb".to_vec()),
                (7usize, Vec::new()),
            ]
        );

        assert_eq!(decode_revealed(&encode_revealed(&[])).unwrap(), vec![]);
    }

    /// Trailing bytes must be rejected: otherwise one revealed set has unboundedly many encodings, and a value that was checked in one form could be presented in another.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn decode_revealed_rejects_trailing_bytes() {
        let base = encode_revealed(&[(0, b"a"), (1, b"b")]);
        assert!(decode_revealed(&base).is_some());

        for suffix in [vec![0u8], vec![0xff], vec![0u8; 64]] {
            let mut padded = base.clone();
            padded.extend_from_slice(&suffix);
            assert!(
                decode_revealed(&padded).is_none(),
                "input with {} trailing byte(s) must be rejected",
                suffix.len()
            );
        }
    }

    /// A count beyond the attribute ceiling is refused before anything is allocated for it.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn decode_revealed_rejects_an_over_large_count() {
        for count in [crate::bbs::MAX_BBS_MESSAGES + 1, u32::MAX] {
            let mut bytes = count.to_be_bytes().to_vec();
            bytes.extend_from_slice(&0u32.to_be_bytes()); // one plausible entry, then truncation
            bytes.extend_from_slice(&0u32.to_be_bytes());
            assert!(
                decode_revealed(&bytes).is_none(),
                "count {count} exceeds the attribute ceiling and must be rejected"
            );
        }
    }

    /// Repeated and out-of-order indices are both refused, so one set has exactly one encoding.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn decode_revealed_rejects_duplicate_and_unsorted_indices() {
        assert!(
            decode_revealed(&encode_revealed(&[(1, b"a"), (1, b"b")])).is_none(),
            "a repeated index must be rejected"
        );
        assert!(
            decode_revealed(&encode_revealed(&[(1, b"a"), (1, b"a")])).is_none(),
            "a repeated index must be rejected even when the values agree"
        );
        assert!(
            decode_revealed(&encode_revealed(&[(2, b"b"), (0, b"a")])).is_none(),
            "unsorted indices must be rejected"
        );
        assert!(decode_revealed(&encode_revealed(&[(0, b"a"), (2, b"b")])).is_some());
    }

    /// Injectivity, stated as the property that matters: for one revealed set, exactly ONE byte string decodes to it.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn decode_revealed_accepts_exactly_one_encoding_per_set() {
        let canonical = encode_revealed(&[(0, b"a"), (2, b"b")]);
        let expected = decode_revealed(&canonical).expect("the canonical form decodes");

        // Every one of these denotes the same set and must be rejected.
        let mut alternatives: Vec<Vec<u8>> = vec![
            encode_revealed(&[(2, b"b"), (0, b"a")]), // permuted
        ];
        for suffix in [vec![0u8], vec![0xffu8; 8]] {
            let mut padded = canonical.clone();
            padded.extend_from_slice(&suffix);
            alternatives.push(padded); // padded
        }
        alternatives.push(encode_revealed(&[(0, b"a"), (0, b"a"), (2, b"b")]));

        for alt in &alternatives {
            assert_ne!(
                alt, &canonical,
                "the alternative must be a different byte string"
            );
            assert!(
                decode_revealed(alt).is_none(),
                "a second encoding of the same revealed set must be rejected"
            );
        }

        assert_eq!(decode_revealed(&canonical).unwrap(), expected);
    }

    /// Truncation anywhere in the buffer is still rejected (the original fail-safe, kept).
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn decode_revealed_rejects_truncation() {
        let full = encode_revealed(&[(0, b"abc"), (1, b"de")]);
        for cut in 1..full.len() {
            assert!(
                decode_revealed(&full[..cut]).is_none(),
                "a buffer truncated at {cut} must be rejected"
            );
        }
        assert!(decode_revealed(&full).is_some());
    }

    #[test]
    fn ffi_signature_roundtrip() {
        let kp = did::generate_keypair(did::Curve::Secp256r1);
        let msg = b"ffi message";
        let sig = did::sign(did::Curve::Secp256r1, &kp.secret, msg).unwrap();
        let ok = unsafe {
            phi_verify_signature(
                1,
                kp.public.as_ptr(),
                kp.public.len(),
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                sig.len(),
            )
        };
        assert_eq!(ok, 1);
        let bad = unsafe {
            phi_verify_signature(
                1,
                kp.public.as_ptr(),
                kp.public.len(),
                b"x".as_ptr(),
                1,
                sig.as_ptr(),
                sig.len(),
            )
        };
        assert_eq!(bad, 0);
    }

    #[test]
    fn ffi_nullifier_writes_32_bytes() {
        let secret = b"voter-secret";
        let topic = b"proposal-1";
        let mut out = [0u8; 32];
        let rc = unsafe {
            phi_compute_nullifier(
                secret.as_ptr(),
                secret.len(),
                topic.as_ptr(),
                topic.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, 1);
        assert_eq!(out, voting::compute_nullifier(secret, topic));
    }

    #[test]
    fn ffi_nullifier_rejects_an_undersized_output_buffer() {
        let secret = b"voter-secret";
        let topic = b"proposal-1";

        // A 31-byte buffer (one short) filled with a sentinel: the export must not write into it.
        let mut small = [0xAAu8; voting::NULLIFIER_LEN - 1];
        let rc = unsafe {
            phi_compute_nullifier(
                secret.as_ptr(),
                secret.len(),
                topic.as_ptr(),
                topic.len(),
                small.as_mut_ptr(),
                small.len(),
            )
        };
        assert_eq!(rc, 0, "an undersized output buffer must fail closed");
        assert_eq!(
            small,
            [0xAAu8; voting::NULLIFIER_LEN - 1],
            "the buffer must be left untouched — no partial/out-of-bounds write"
        );

        let mut buf = [0xAAu8; 64];
        let rc = unsafe {
            phi_compute_nullifier(
                secret.as_ptr(),
                secret.len(),
                topic.as_ptr(),
                topic.len(),
                buf.as_mut_ptr(),
                0,
            )
        };
        assert_eq!(
            rc, 0,
            "out_len below NULLIFIER_LEN must fail closed regardless of the true allocation"
        );
        assert_eq!(
            buf, [0xAAu8; 64],
            "nothing is written when out_len is under the required length"
        );

        let rc = unsafe {
            phi_compute_nullifier(
                secret.as_ptr(),
                secret.len(),
                topic.as_ptr(),
                topic.len(),
                buf.as_mut_ptr(),
                buf.len(),
            )
        };
        assert_eq!(rc, 1, "a buffer at/above NULLIFIER_LEN is accepted");
        assert_eq!(
            buf[..voting::NULLIFIER_LEN],
            voting::compute_nullifier(secret, topic)
        );
        assert_eq!(
            buf[voting::NULLIFIER_LEN..],
            [0xAAu8; 64 - voting::NULLIFIER_LEN],
            "only the first NULLIFIER_LEN bytes are written"
        );
    }

    #[test]
    fn ffi_bbs2023_verify_proof_roundtrip() {
        use crate::bbs::CryptoSuite;
        use crate::bbs_2023::Bbs2023Sha256;

        let claims = vec![b"a=1".to_vec(), b"b=2".to_vec(), b"c=3".to_vec()];
        let kp = Bbs2023Sha256::generate_keypair(3).unwrap();
        let cred = Bbs2023Sha256::sign_credential(&claims, &kp.secret).unwrap();
        let proof = Bbs2023Sha256::derive_proof(&claims, &cred, &[1], b"ph").unwrap();

        let mut revealed = Vec::new();
        revealed.extend_from_slice(&(proof.revealed.len() as u32).to_be_bytes());
        for (index, value) in &proof.revealed {
            revealed.extend_from_slice(&index.to_be_bytes());
            revealed.extend_from_slice(&(value.len() as u32).to_be_bytes());
            revealed.extend_from_slice(value);
        }

        let header: &[u8] = &[];
        let ok = unsafe {
            phi_bbs2023_verify_proof(
                proof.proof.as_ptr(),
                proof.proof.len(),
                kp.public.as_ptr(),
                kp.public.len(),
                header.as_ptr(),
                header.len(),
                b"ph".as_ptr(),
                2,
                revealed.as_ptr(),
                revealed.len(),
            )
        };
        assert_eq!(ok, 1);
        // Wrong presentation header must be rejected.
        let bad = unsafe {
            phi_bbs2023_verify_proof(
                proof.proof.as_ptr(),
                proof.proof.len(),
                kp.public.as_ptr(),
                kp.public.len(),
                header.as_ptr(),
                header.len(),
                b"other".as_ptr(),
                5,
                revealed.as_ptr(),
                revealed.len(),
            )
        };
        assert_eq!(bad, 0);
    }

    #[test]
    fn ffi_rejects_null_with_nonzero_len() {
        let rc = unsafe {
            phi_verify_signature(
                1,
                core::ptr::null(),
                33,
                b"x".as_ptr(),
                1,
                b"y".as_ptr(),
                64,
            )
        };
        assert_eq!(rc, 0);
    }

    /// The `guard` wrapper turns a panic into the fail-closed return rather than letting it reach C.
    #[test]
    fn guard_converts_a_panic_into_the_fail_closed_value() {
        // Silence the default panic hook so a deliberate panic does not print a scary backtrace.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let rc = guard(0, || -> i32 {
            panic!("simulated internal invariant failure")
        });
        std::panic::set_hook(previous);

        assert_eq!(rc, 0, "a caught panic must return the fail-closed value");
    }

    /// …and a body that succeeds is passed through untouched, so the wrapper cannot silently turn a valid verification into a rejection.
    #[test]
    fn guard_passes_a_successful_result_through() {
        assert_eq!(guard(0, || 1), 1);
        assert_eq!(guard(0, || 0), 0);
    }

    /// A real export with valid input still succeeds through the wrapper — the round trip that would break if `guard` swallowed or altered results.
    #[test]
    fn wrapped_export_still_accepts_valid_input() {
        let kp = did::generate_keypair(did::Curve::Secp256r1);
        let msg = b"phi ffi guard round trip";
        let sig = did::sign(did::Curve::Secp256r1, &kp.secret, msg).expect("sign");
        let rc = unsafe {
            phi_verify_signature(
                1,
                kp.public.as_ptr(),
                kp.public.len(),
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                sig.len(),
            )
        };
        assert_eq!(rc, 1, "a valid signature must still verify through guard");
    }

    #[test]
    fn ffi_bbs2023_and_nullifier_reject_bad_input() {
        let rc = unsafe {
            phi_bbs2023_verify_proof(
                core::ptr::null(),
                64,
                b"pk".as_ptr(),
                2,
                b"".as_ptr(),
                0,
                b"ph".as_ptr(),
                2,
                b"".as_ptr(),
                0,
            )
        };
        assert_eq!(rc, 0, "null proof must be rejected");
        let rc = unsafe {
            phi_bbs2023_verify_proof(
                b"p".as_ptr(),
                1,
                b"pk".as_ptr(),
                2,
                b"".as_ptr(),
                0,
                b"ph".as_ptr(),
                2,
                core::ptr::null(),
                4,
            )
        };
        assert_eq!(rc, 0, "null revealed pointer must be rejected");
        // phi_compute_nullifier: a null output buffer must fail closed (no write).
        let rc = unsafe {
            phi_compute_nullifier(
                b"s".as_ptr(),
                1,
                b"t".as_ptr(),
                1,
                core::ptr::null_mut(),
                32,
            )
        };
        assert_eq!(rc, 0, "null output buffer must be rejected");
        // null secret pointer with a non-zero length.
        let mut out = [0u8; 32];
        let rc = unsafe {
            phi_compute_nullifier(
                core::ptr::null(),
                8,
                b"t".as_ptr(),
                1,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, 0, "null secret must be rejected");
    }

    /// A `SelectiveProof` wire buffer with a hostile `message_count` and empty proof/revealed.
    fn hostile_proof_bytes(message_count: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&message_count.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // proof length
        out.extend_from_slice(&0u32.to_be_bytes()); // revealed count
        out
    }

    #[test]
    fn ffi_bbs_verify_rejects_hostile_message_count() {
        for &mc in &[0u32, u32::MAX - 1] {
            let buf = hostile_proof_bytes(mc);
            let rc = unsafe {
                phi_bbs_verify_proof(buf.as_ptr(), buf.len(), b"pk".as_ptr(), 2, b"n".as_ptr(), 1)
            };
            assert_eq!(rc, 0, "phi_bbs_verify_proof must reject message_count={mc}");

            let null = [0u8; crate::voting::NULLIFIER_LEN];
            let rc = unsafe {
                phi_semaphore_verify_vote(
                    buf.as_ptr(),
                    buf.len(),
                    b"pk".as_ptr(),
                    2,
                    b"election".as_ptr(),
                    8,
                    null.as_ptr(),
                    null.len(),
                    b"signal".as_ptr(),
                    6,
                )
            };
            assert_eq!(
                rc, 0,
                "phi_semaphore_verify_vote must reject message_count={mc}"
            );
        }
    }
}

/// FFI-boundary tests for the composed `voting_snark` export.
#[cfg(all(test, feature = "voting_snark"))]
mod voting_snark_ffi_tests {
    use super::*;
    use crate::bbs;
    use crate::voting_snark::prove_vote;

    /// Fixed chain-id these C-ABI boundary tests are pinned to; the export now binds it.
    const TEST_CHAIN: &[u8] = b"phi-testnet-1";

    /// A BBS+ credential whose index-0 claim is a high-entropy voter secret, plus a valid composed vote proof over it and the caller-side arguments the C-ABI takes.
    struct Fixture {
        public_key: Vec<u8>,
        election: &'static [u8],
        signal: &'static [u8],
        proof_bytes: Vec<u8>,
        nullifier: Vec<u8>,
    }

    fn fixture() -> Fixture {
        let claims = vec![
            b"voter_secret=9f2c1a7b4e6d8003".to_vec(), // index 0 (VOTER_SECRET_MSG_INDEX)
            b"region=north".to_vec(),
            b"cohort=2025".to_vec(),
        ];
        let kp = bbs::generate_keypair(claims.len() as u32).unwrap();
        let sig = bbs::sign_credential(&claims, &kp.secret).unwrap();
        let election: &[u8] = b"election-1";
        let signal: &[u8] = b"option-2";
        let proof = prove_vote(
            &claims,
            &sig,
            &kp.public,
            &[1],
            TEST_CHAIN,
            election,
            signal,
        )
        .unwrap();
        Fixture {
            public_key: kp.public,
            election,
            signal,
            nullifier: proof.nullifier_bytes().unwrap().to_vec(),
            proof_bytes: proof.to_bytes().unwrap(),
        }
    }

    /// Drive the export from a `Fixture`, allowing individual arguments to be overridden per test.
    fn call(
        proof_bytes: &[u8],
        public_key: &[u8],
        election: &[u8],
        nullifier: &[u8],
        signal: &[u8],
    ) -> i32 {
        unsafe {
            phi_voting_verify_vote_v1(
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                public_key.as_ptr(),
                public_key.len(),
                TEST_CHAIN.as_ptr(),
                TEST_CHAIN.len(),
                election.as_ptr(),
                election.len(),
                nullifier.as_ptr(),
                nullifier.len(),
                signal.as_ptr(),
                signal.len(),
            )
        }
    }

    #[test]
    fn valid_proof_accepts_roundtrip() {
        let f = fixture();
        let rc = call(
            &f.proof_bytes,
            &f.public_key,
            f.election,
            &f.nullifier,
            f.signal,
        );
        assert_eq!(rc, 1, "a prove_vote output must verify through the C-ABI");
    }

    #[test]
    fn tampered_proof_rejected() {
        let f = fixture();
        let mut bad = f.proof_bytes.clone();
        bad[9] ^= 0xff;
        let rc = call(&bad, &f.public_key, f.election, &f.nullifier, f.signal);
        assert_eq!(rc, 0, "a tampered proof must be rejected");
    }

    #[test]
    fn wrong_signal_rejected() {
        let f = fixture();
        let rc = call(
            &f.proof_bytes,
            &f.public_key,
            f.election,
            &f.nullifier,
            b"option-9",
        );
        assert_eq!(
            rc, 0,
            "a signal the ballot was not bound to must be rejected"
        );
    }

    #[test]
    fn wrong_issuer_key_rejected() {
        let f = fixture();
        let other = bbs::generate_keypair(3).unwrap();
        let rc = call(
            &f.proof_bytes,
            &other.public,
            f.election,
            &f.nullifier,
            f.signal,
        );
        assert_eq!(rc, 0, "a wrong issuer public key must be rejected");
    }

    #[test]
    fn wrong_election_rejected() {
        let f = fixture();
        let rc = call(
            &f.proof_bytes,
            &f.public_key,
            b"election-2",
            &f.nullifier,
            f.signal,
        );
        assert_eq!(
            rc, 0,
            "verifying under a different election must be rejected"
        );
    }

    #[test]
    fn tampered_nullifier_rejected() {
        let f = fixture();
        let mut bad_null = f.nullifier.clone();
        bad_null[0] ^= 0x01;
        let rc = call(
            &f.proof_bytes,
            &f.public_key,
            f.election,
            &bad_null,
            f.signal,
        );
        assert_eq!(
            rc, 0,
            "a nullifier that differs from the proof's must be rejected"
        );
    }

    #[test]
    fn unrelated_valid_nullifier_rejected() {
        let f = fixture();
        let claims = vec![
            b"voter_secret=9f2c1a7b4e6d8003".to_vec(),
            b"region=north".to_vec(),
            b"cohort=2025".to_vec(),
        ];
        let kp = bbs::generate_keypair(3).unwrap();
        let sig = bbs::sign_credential(&claims, &kp.secret).unwrap();
        let other = prove_vote(
            &claims,
            &sig,
            &kp.public,
            &[1],
            TEST_CHAIN,
            b"election-9",
            f.signal,
        )
        .unwrap();
        let other_null = other.nullifier_bytes().unwrap().to_vec();
        assert_ne!(other_null, f.nullifier);
        let rc = call(
            &f.proof_bytes,
            &f.public_key,
            f.election,
            &other_null,
            f.signal,
        );
        assert_eq!(rc, 0, "an unrelated (but valid) nullifier must be rejected");
    }

    #[test]
    fn wrong_length_nullifier_rejected() {
        let f = fixture();
        let short = vec![0u8; 32]; // 32 bytes: the 48-byte try_into fails closed
        let rc = call(&f.proof_bytes, &f.public_key, f.election, &short, f.signal);
        assert_eq!(rc, 0, "a nullifier that is not 48 bytes must be rejected");
    }

    #[test]
    fn malformed_and_truncated_proof_rejected() {
        let f = fixture();
        assert_eq!(
            call(&[], &f.public_key, f.election, &f.nullifier, f.signal),
            0
        );
        let truncated = &f.proof_bytes[..f.proof_bytes.len().min(10)];
        assert_eq!(
            call(truncated, &f.public_key, f.election, &f.nullifier, f.signal),
            0
        );
        let mut extended = f.proof_bytes.clone();
        extended.push(0xaa);
        assert_eq!(
            call(&extended, &f.public_key, f.election, &f.nullifier, f.signal),
            0
        );
    }

    #[test]
    fn null_pointers_rejected() {
        let f = fixture();
        let rc = unsafe {
            phi_voting_verify_vote_v1(
                core::ptr::null(),
                64,
                f.public_key.as_ptr(),
                f.public_key.len(),
                TEST_CHAIN.as_ptr(),
                TEST_CHAIN.len(),
                f.election.as_ptr(),
                f.election.len(),
                f.nullifier.as_ptr(),
                f.nullifier.len(),
                f.signal.as_ptr(),
                f.signal.len(),
            )
        };
        assert_eq!(rc, 0, "null proof pointer must be rejected");
        let rc = unsafe {
            phi_voting_verify_vote_v1(
                f.proof_bytes.as_ptr(),
                f.proof_bytes.len(),
                core::ptr::null(),
                96,
                TEST_CHAIN.as_ptr(),
                TEST_CHAIN.len(),
                f.election.as_ptr(),
                f.election.len(),
                f.nullifier.as_ptr(),
                f.nullifier.len(),
                f.signal.as_ptr(),
                f.signal.len(),
            )
        };
        assert_eq!(rc, 0, "null public-key pointer must be rejected");
        let rc = unsafe {
            phi_voting_verify_vote_v1(
                f.proof_bytes.as_ptr(),
                f.proof_bytes.len(),
                f.public_key.as_ptr(),
                f.public_key.len(),
                TEST_CHAIN.as_ptr(),
                TEST_CHAIN.len(),
                f.election.as_ptr(),
                f.election.len(),
                core::ptr::null(),
                48,
                f.signal.as_ptr(),
                f.signal.len(),
            )
        };
        assert_eq!(rc, 0, "null nullifier pointer must be rejected");
    }

    #[test]
    fn wrong_chain_id_rejected() {
        let f = fixture();
        let other_chain: &[u8] = b"phi-mainnet-1";
        let rc = unsafe {
            phi_voting_verify_vote_v1(
                f.proof_bytes.as_ptr(),
                f.proof_bytes.len(),
                f.public_key.as_ptr(),
                f.public_key.len(),
                other_chain.as_ptr(),
                other_chain.len(),
                f.election.as_ptr(),
                f.election.len(),
                f.nullifier.as_ptr(),
                f.nullifier.len(),
                f.signal.as_ptr(),
                f.signal.len(),
            )
        };
        assert_eq!(
            rc, 0,
            "a proof bound to one chain-id must not verify under another"
        );
        assert_eq!(
            call(
                &f.proof_bytes,
                &f.public_key,
                f.election,
                &f.nullifier,
                f.signal
            ),
            1,
            "the proof still verifies under the chain-id it was bound to"
        );
    }
}
