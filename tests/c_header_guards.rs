// SPDX-License-Identifier: Apache-2.0
//! The two C-ABI headers must be independently includable.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_header(name: &str) -> String {
    std::fs::read_to_string(repo_root().join(name)).expect("header must exist")
}

/// Each header owns its own guard.
#[test]
fn headers_use_distinct_include_guards() {
    fn guard_of(src: &str) -> String {
        src.lines()
            .find_map(|l| l.strip_prefix("#ifndef "))
            .expect("header must have an include guard")
            .trim()
            .to_string()
    }

    let base = guard_of(&read_header("phi_crypto.h"));
    let snark = guard_of(&read_header("phi_crypto_voting_snark.h"));

    assert_ne!(
        base, snark,
        "the two headers must not share an include guard: the second included would expand to nothing"
    );
    assert_eq!(base, "PHI_CRYPTO_H");
    assert_eq!(snark, "PHI_CRYPTO_VOTING_SNARK_H");
}

/// The featured header really is the default one plus the gated export — the overlap that makes a shared guard dangerous, and the reason the gated symbol is what goes missing.
#[test]
fn featured_header_is_a_superset_of_the_default() {
    let base = read_header("phi_crypto.h");
    let snark = read_header("phi_crypto_voting_snark.h");

    for symbol in [
        "phi_verify_signature",
        "phi_webauthn_verify",
        "phi_bbs_verify_proof",
        "phi_bbs2023_verify_proof",
        "phi_compute_nullifier",
        "phi_semaphore_verify_vote",
    ] {
        assert!(
            base.contains(symbol),
            "{symbol} missing from the default header"
        );
        assert!(
            snark.contains(symbol),
            "{symbol} missing from the featured header"
        );
    }
    assert!(
        !base.contains("phi_voting_verify_vote_v1"),
        "the gated export must not appear in the default header"
    );
    assert!(
        snark.contains("phi_voting_verify_vote_v1"),
        "the gated export must appear in the featured header"
    );
}

/// Compile a translation unit that includes BOTH headers and references every symbol.
#[test]
fn both_headers_compile_in_one_translation_unit() {
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    if Command::new(&cc).arg("--version").output().is_err() {
        eprintln!("no C compiler ({cc}) available — skipping the compile check");
        return;
    }

    let root = repo_root();
    let out = std::env::temp_dir().join("phi_crypto_both_headers.o");
    let output = Command::new(&cc)
        .args(["-std=c99", "-Wall", "-Wextra", "-Werror", "-c"])
        .arg("-I")
        .arg(&root)
        .arg(root.join("tests/c/both_headers.c"))
        .arg("-o")
        .arg(&out)
        .output()
        .expect("failed to run the C compiler");

    assert!(
        output.status.success(),
        "including both headers in one translation unit must compile:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_file(out);
}
