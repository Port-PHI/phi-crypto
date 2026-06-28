// SPDX-License-Identifier: Apache-2.0
//! C-ABI boundary for non-Rust consumers — primarily phi-chain (Go/cgo).
//!
//! This is the **only module where `unsafe` is permitted** (working with raw pointers from C).
//! Boundary rules:
//! - **No panic must escape to C** — all functions return an error code / `0` on bad input.
//! - Verification functions are boolean: `1` = valid, `0` = invalid/bad input (fail-safe default).
//! - Pointers are read-only; no ownership is taken from or handed to C except the caller-preallocated
//!   output buffer (nullifier).
//!
//! Example consumption in Go (phi-chain):
//! ```ignore
//! // #cgo LDFLAGS: -L./lib -lphi_crypto
//! // #include "phi_crypto.h"
//! import "C"
//! ```

#![allow(unsafe_code)]

use core::slice;

use crate::{bbs, did, voting, webauthn};

/// Convert pointer+length into a slice; `None` if the pointer is null with non-zero length.
///
/// This null-checks the pointer (so `(null, 0)` is the empty slice, not UB) but it CANNOT validate
/// `len`: a slice of `len` bytes is constructed and read. `len` is attacker-influenced data crossing
/// the C-ABI, so the safety of the read rests entirely on the calling convention below.
///
/// # Safety
/// The caller MUST guarantee that, whenever `len > 0`, `ptr` points to a single allocated object of at
/// least `len` readable bytes that stays valid and immutable for the entire call. In particular the
/// caller must pass the buffer's true length as `len` (never a larger value): an over-stated `len`
/// causes an out-of-bounds read. The phi-chain cgo bindings satisfy this by deriving every `len` from
/// the corresponding Go slice's `len()` via `C.size_t(len(b))` and pinning the backing array for the
/// duration of the call.
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
///
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

/// Verify an ECDSA signature (k1/r1). Output: `1` valid, `0` invalid/bad input.
///
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
    let (Some(curve), Some(pk), Some(m), Some(s)) = (
        curve_from_code(curve_code),
        as_slice(public_key, public_key_len),
        as_slice(msg, msg_len),
        as_slice(sig, sig_len),
    ) else {
        return 0;
    };
    did::verify(curve, pk, m, s) as i32
}

/// Verify a WebAuthn assertion (P-256). Output: `1` valid, `0` invalid/bad input.
///
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
) -> i32 {
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
    webauthn::verify_webauthn(&assertion, ch, pk, org, rp) as i32
}

/// Verify a BBS+ selective-disclosure proof (proof as serialized bytes). Output: `1` valid, `0` otherwise.
///
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
    let (Some(p), Some(pk), Some(n)) = (
        as_slice(proof, proof_len),
        as_slice(public_key, public_key_len),
        as_slice(nonce, nonce_len),
    ) else {
        return 0;
    };
    bbs::verify_proof_bytes(p, pk, n) as i32
}

/// Decode a length-prefixed list of revealed messages for bbs-2023 proof verification.
/// Wire format (big-endian): `count: u32`, then for each entry `index: u32`, `len: u32`,
/// `bytes[len]`. Returns `None` on any truncation (fail-safe). Mirrors the `revealed` encoding in
/// [`crate::bbs::SelectiveProof::to_bytes`].
#[cfg(not(target_arch = "wasm32"))]
fn decode_revealed(b: &[u8]) -> Option<Vec<(usize, Vec<u8>)>> {
    fn u32_at(b: &[u8], pos: &mut usize) -> Option<u32> {
        let end = pos.checked_add(4)?;
        let bytes = b.get(*pos..end)?;
        *pos = end;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }
    let mut pos = 0usize;
    let count = u32_at(b, &mut pos)? as usize;
    let mut out = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let index = u32_at(b, &mut pos)? as usize;
        let len = u32_at(b, &mut pos)? as usize;
        let end = pos.checked_add(len)?;
        let value = b.get(pos..end)?.to_vec();
        out.push((index, value));
        pos = end;
    }
    Some(out)
}

/// Verify a W3C `bbs-2023` (BLS12-381 SHA-256) selective-disclosure proof. `revealed` is the
/// length-prefixed encoding decoded by `decode_revealed`. Output: `1` valid, `0` invalid/bad
/// input. Native targets only (the bbs-2023 suite is gated out on wasm32).
///
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
}

/// Compute a nullifier; writes 32 bytes into `out` (caller-allocated).
/// Output: `1` success, `0` bad input.
///
/// # Safety
/// `out` must point to a writable buffer of at least 32 bytes; the rest must be readable regions.
#[no_mangle]
pub unsafe extern "C" fn phi_compute_nullifier(
    secret: *const u8,
    secret_len: usize,
    topic: *const u8,
    topic_len: usize,
    out: *mut u8,
) -> i32 {
    let (Some(sec), Some(top)) = (as_slice(secret, secret_len), as_slice(topic, topic_len)) else {
        return 0;
    };
    if out.is_null() {
        return 0;
    }
    let n = voting::compute_nullifier(sec, top);
    // Copy 32 bytes into the output buffer.
    let out_slice = slice::from_raw_parts_mut(out, voting::NULLIFIER_LEN);
    out_slice.copy_from_slice(&n);
    1
}

/// Verify a BBS eligibility proof bound to `(election_id, nullifier, signal)` (Semaphore binding
/// layer). `signal` is the canonical encoding of the voter's chosen option; binding it makes the
/// accepted ballot non-malleable. `nullifier` must point to 32 bytes. Output: `1` valid, `0`
/// invalid/bad input.
///
/// **Not Sybil-resistant on its own:** this verifies eligibility and binds the proof to a
/// single nullifier and option, but does not prove the nullifier derives from a signed credential
/// secret, so a caller must not treat a `1` as one-credential-one-vote.
/// See [`crate::semaphore::verify_bound_proof`].
///
/// # Safety
/// All pointers must reference readable regions of the stated lengths; `nullifier` must be 32 bytes.
/// A zero-length `signal` is permitted (`signal` may be null only when `signal_len == 0`).
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Tampered signature.
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
            )
        };
        assert_eq!(rc, 1);
        assert_eq!(out, voting::compute_nullifier(secret, topic));
    }

    #[test]
    fn ffi_bbs2023_verify_proof_roundtrip() {
        use crate::bbs::CryptoSuite;
        use crate::bbs_2023::Bbs2023Sha256;

        let claims = vec![b"a=1".to_vec(), b"b=2".to_vec(), b"c=3".to_vec()];
        let kp = Bbs2023Sha256::generate_keypair(3).unwrap();
        let cred = Bbs2023Sha256::sign_credential(&claims, &kp.secret).unwrap();
        let proof = Bbs2023Sha256::derive_proof(&claims, &cred, &[1], b"ph").unwrap();

        // Encode revealed messages with the wire format decode_revealed expects.
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

    // the two newer C-ABI exports must fail closed on null/empty input — never panic or read
    // out of bounds across the FFI boundary. (Continuous fuzzing of these entry points is wired as a
    // cargo-fuzz target run in CI; this test pins the deterministic fail-closed cases.)
    #[test]
    fn ffi_bbs2023_and_nullifier_reject_bad_input() {
        // null proof pointer with a non-zero length.
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
        // null revealed pointer with a non-zero length.
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
            phi_compute_nullifier(b"s".as_ptr(), 1, b"t".as_ptr(), 1, core::ptr::null_mut())
        };
        assert_eq!(rc, 0, "null output buffer must be rejected");
        // null secret pointer with a non-zero length.
        let mut out = [0u8; 32];
        let rc = unsafe {
            phi_compute_nullifier(core::ptr::null(), 8, b"t".as_ptr(), 1, out.as_mut_ptr())
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
        // Both BBS verification entry points decode through SelectiveProof::from_bytes, so a
        // degenerate (0) or oversized (near u32::MAX) message_count returns 0 without allocating.
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
