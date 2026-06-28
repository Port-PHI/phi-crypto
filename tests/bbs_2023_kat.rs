// SPDX-License-Identifier: Apache-2.0
//! Known-answer tests for the `bbs_2023` suite against the official IETF/W3C `bbs-2023`
//! (BLS12-381 SHA-256) fixtures committed under `tests/vectors/bbs_2023_sha256/` (see `SOURCE.md`).
//!
//! - `signature/*.json`: for valid cases, deterministic signing must reproduce the official
//!   signature byte-for-byte, and verification must accept it; for invalid cases, verification must
//!   reject the (modified) signature/messages.
//! - `proof/*.json`: proof verification must match the fixture's expected result.

use std::{fs, path::Path, path::PathBuf};

use phi_crypto::bbs_2023;
use serde_json::Value;

fn hex_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string field")).expect("valid hex")
}

fn vectors_dir(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/bbs_2023_sha256")
        .join(sub)
}

fn json_files(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|_| panic!("missing fixtures dir {dir:?}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
}

#[test]
fn w3c_signature_vectors() {
    let mut count = 0;
    for path in json_files(&vectors_dir("signature")) {
        let f: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().to_string();

        let sk = hex_bytes(&f["signerKeyPair"]["secretKey"]);
        let pk = hex_bytes(&f["signerKeyPair"]["publicKey"]);
        let header = hex_bytes(&f["header"]);
        let messages: Vec<Vec<u8>> = f["messages"]
            .as_array()
            .map(|a| a.iter().map(hex_bytes).collect())
            .unwrap_or_default();
        let expected_sig = hex_bytes(&f["signature"]);
        let valid = f["result"]["valid"].as_bool().unwrap();

        if valid {
            // Deterministic signing reproduces the official signature byte-for-byte.
            let sig = bbs_2023::sign(&sk, &pk, &header, &messages)
                .unwrap_or_else(|_| panic!("sign failed for {name}"));
            assert_eq!(sig, expected_sig, "signature byte mismatch in {name}");
            assert!(
                bbs_2023::verify(&pk, &header, &messages, &expected_sig),
                "verification should accept {name}"
            );
        } else {
            assert!(
                !bbs_2023::verify(&pk, &header, &messages, &expected_sig),
                "verification should reject {name}"
            );
        }
        count += 1;
    }
    assert!(
        count >= 9,
        "expected the official signature fixtures, found {count}"
    );
}

#[test]
fn w3c_proof_vectors() {
    let mut count = 0;
    for path in json_files(&vectors_dir("proof")) {
        let f: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().to_string();

        let pk = hex_bytes(&f["signerPublicKey"]);
        let header = hex_bytes(&f["header"]);
        let presentation_header = hex_bytes(&f["presentationHeader"]);
        let proof = hex_bytes(&f["proof"]);
        let valid = f["result"]["valid"].as_bool().unwrap();

        let mut revealed: Vec<(usize, Vec<u8>)> = f["revealedMessages"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.parse::<usize>().expect("index key"), hex_bytes(v)))
                    .collect()
            })
            .unwrap_or_default();
        revealed.sort_by_key(|(i, _)| *i);

        let got = bbs_2023::proof_verify(&pk, &header, &presentation_header, &proof, &revealed);
        assert_eq!(got, valid, "proof_verify result mismatch in {name}");
        count += 1;
    }
    assert!(
        count >= 15,
        "expected the official proof fixtures, found {count}"
    );
}
