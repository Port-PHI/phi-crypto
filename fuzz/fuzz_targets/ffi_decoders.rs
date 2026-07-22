// SPDX-License-Identifier: Apache-2.0
//! Fuzz the C-ABI decoders with arbitrary attacker-controlled bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

use phi_crypto::ffi::{
    phi_bbs2023_verify_proof, phi_bbs_verify_proof, phi_compute_nullifier,
    phi_semaphore_verify_vote, phi_verify_signature, phi_webauthn_verify,
};

/// Splits the fuzzer's buffer into `n` pieces at positions the fuzzer itself chooses.
fn split<'a>(data: &'a [u8], n: usize) -> Vec<&'a [u8]> {
    if data.len() < n {
        return vec![&data[..0]; n];
    }
    let (ratios, body) = data.split_at(n - 1);
    let mut out = Vec::with_capacity(n);
    let mut rest = body;
    for &r in ratios {
        let take = (rest.len() * r as usize) / 256;
        let (head, tail) = rest.split_at(take.min(rest.len()));
        out.push(head);
        rest = tail;
    }
    out.push(rest);
    out
}

/// Every export is boolean at the C-ABI: `1` valid, `0` invalid or bad input.
fn assert_boolean(rc: i32, which: &str) {
    assert!(rc == 0 || rc == 1, "{which} returned {rc}, not 0 or 1");
}

fuzz_target!(|data: &[u8]| {
    let parts = split(data, 5);
    let rc = unsafe {
        phi_bbs2023_verify_proof(
            parts[0].as_ptr(),
            parts[0].len(),
            parts[1].as_ptr(),
            parts[1].len(),
            parts[2].as_ptr(),
            parts[2].len(),
            parts[3].as_ptr(),
            parts[3].len(),
            parts[4].as_ptr(),
            parts[4].len(),
        )
    };
    assert_boolean(rc, "phi_bbs2023_verify_proof");

    let rc = unsafe {
        phi_bbs2023_verify_proof(
            data.as_ptr(),
            data.len(),
            data.as_ptr(),
            data.len(),
            data.as_ptr(),
            0,
            data.as_ptr(),
            0,
            data.as_ptr(),
            data.len(),
        )
    };
    assert_boolean(rc, "phi_bbs2023_verify_proof (revealed = whole buffer)");

    let parts = split(data, 3);
    let rc = unsafe {
        phi_bbs_verify_proof(
            parts[0].as_ptr(),
            parts[0].len(),
            parts[1].as_ptr(),
            parts[1].len(),
            parts[2].as_ptr(),
            parts[2].len(),
        )
    };
    assert_boolean(rc, "phi_bbs_verify_proof");

    let parts = split(data, 5);
    let rc = unsafe {
        phi_semaphore_verify_vote(
            parts[0].as_ptr(),
            parts[0].len(),
            parts[1].as_ptr(),
            parts[1].len(),
            parts[2].as_ptr(),
            parts[2].len(),
            parts[3].as_ptr(),
            parts[3].len(),
            parts[4].as_ptr(),
            parts[4].len(),
        )
    };
    assert_boolean(rc, "phi_semaphore_verify_vote");

    let parts = split(data, 3);
    let curve_code = data.first().copied().unwrap_or(0);
    let rc = unsafe {
        phi_verify_signature(
            curve_code,
            parts[0].as_ptr(),
            parts[0].len(),
            parts[1].as_ptr(),
            parts[1].len(),
            parts[2].as_ptr(),
            parts[2].len(),
        )
    };
    assert_boolean(rc, "phi_verify_signature");

    let parts = split(data, 7);
    let rc = unsafe {
        phi_webauthn_verify(
            parts[0].as_ptr(),
            parts[0].len(),
            parts[1].as_ptr(),
            parts[1].len(),
            parts[2].as_ptr(),
            parts[2].len(),
            parts[3].as_ptr(),
            parts[3].len(),
            parts[4].as_ptr(),
            parts[4].len(),
            parts[5].as_ptr(),
            parts[5].len(),
            parts[6].as_ptr(),
            parts[6].len(),
            (curve_code & 1) as i32,
        )
    };
    assert_boolean(rc, "phi_webauthn_verify");

    let parts = split(data, 2);
    let mut out = [0u8; 48];
    let rc = unsafe {
        phi_compute_nullifier(
            parts[0].as_ptr(),
            parts[0].len(),
            parts[1].as_ptr(),
            parts[1].len(),
            out.as_mut_ptr().add(8),
        )
    };
    assert_boolean(rc, "phi_compute_nullifier");
    assert!(
        out[..8].iter().all(|&b| b == 0) && out[40..].iter().all(|&b| b == 0),
        "phi_compute_nullifier wrote outside its 32-byte output buffer"
    );
});
