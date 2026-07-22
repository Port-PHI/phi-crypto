// SPDX-License-Identifier: Apache-2.0
//! No secret leaves Rust as an extra, un-wiped copy.

use std::fs;
use std::path::{Path, PathBuf};

use phi_crypto::secret::into_boundary_owned;
use phi_crypto::{bbs, bbs::CryptoSuite, did, seed};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// The recovery phrase: `seed::generate_mnemonic` → boundary.
#[test]
fn mnemonic_path_moves_rather_than_copies() {
    let phrase = seed::generate_mnemonic();
    assert!(!phrase.is_empty(), "a phrase must have been generated");
    let before = phrase.as_ptr();
    let expected = phrase.to_string();

    let owned = into_boundary_owned(phrase);

    assert_eq!(owned, expected, "the phrase must survive the move intact");
    assert_eq!(
        before,
        owned.as_ptr(),
        "the phrase handed across must be the original allocation, not a second copy"
    );
}

/// The self-custody k1 private key: `seed::derive_k1_keypair` → boundary.
#[test]
fn seed_derived_k1_secret_path_moves_rather_than_copies() {
    let phrase = seed::generate_mnemonic();
    let kp = seed::derive_k1_keypair(&phrase, "").expect("derive");
    assert_eq!(kp.secret.len(), 32, "a k1 secret scalar is 32 bytes");

    let before = kp.secret.as_ptr();
    let expected = kp.secret.to_vec();

    let owned = into_boundary_owned(kp.secret);

    assert_eq!(owned, expected);
    assert_eq!(
        before,
        owned.as_ptr(),
        "the k1 secret handed across must be the original allocation"
    );
}

/// The randomly generated DID private key, on both curves: `did::generate_keypair` → boundary.
#[test]
fn did_keypair_secret_path_moves_rather_than_copies() {
    for curve in [did::Curve::Secp256k1, did::Curve::Secp256r1] {
        let kp = did::generate_keypair(curve);
        let before = kp.secret.as_ptr();
        let expected = kp.secret.to_vec();

        let owned = into_boundary_owned(kp.secret);

        assert_eq!(owned, expected);
        assert_eq!(
            before,
            owned.as_ptr(),
            "the {curve:?} secret handed across must be the original allocation"
        );
    }
}

/// The BBS+ issuer secret: `bbs::generate_keypair` → boundary.
#[test]
fn bbs_issuer_secret_path_moves_rather_than_copies() {
    let kp = bbs::DocknetBbsPlus::generate_keypair(3).expect("keypair");
    let before = kp.secret.as_ptr();
    let expected = kp.secret.to_vec();

    let owned = into_boundary_owned(kp.secret);

    assert_eq!(owned, expected);
    assert_eq!(
        before,
        owned.as_ptr(),
        "the issuer secret handed across must be the original allocation"
    );
}

/// The files that hand secrets to a foreign runtime.
fn boundary_sources() -> Vec<(&'static str, String)> {
    let root = repo_root();
    let paths = [
        ("src/wasm.rs", root.join("src/wasm.rs")),
        (
            "bindings/flutter/rust/src/api.rs",
            root.join("bindings/flutter/rust/src/api.rs"),
        ),
    ];
    paths
        .into_iter()
        .map(|(label, path)| {
            let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {label}: {e}"));
            (label, text)
        })
        .collect()
}

/// Neither boundary may copy a secret out of its wrapper.
#[test]
fn boundary_sources_never_copy_a_secret_out_of_its_wrapper() {
    let forbidden = [
        "kp.secret.to_vec()",
        "generate_mnemonic().to_string()",
        "secret.clone()",
    ];

    for (label, text) in boundary_sources() {
        for pattern in forbidden {
            let offending = text
                .lines()
                .filter(|line| line.contains(pattern))
                .filter(|line| !line.trim_start().starts_with("//"))
                .filter(|line| !line.contains("self.secret.clone()"))
                .count();
            assert_eq!(
                offending, 0,
                "{label} still copies a secret out of its wrapper via `{pattern}`; \
                 move it with phi_crypto::secret::into_boundary_owned instead"
            );
        }
    }
}

/// And each boundary must actually use the move helper, so the check above cannot pass merely because someone deleted the hand-off.
#[test]
fn boundary_sources_use_the_move_helper() {
    for (label, text) in boundary_sources() {
        let uses = text.matches("into_boundary_owned(").count();
        assert!(
            uses >= 4,
            "{label} should hand every secret over with into_boundary_owned (found {uses})"
        );
    }
}
