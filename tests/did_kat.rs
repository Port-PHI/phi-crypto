// SPDX-License-Identifier: Apache-2.0
//! Cross-language known-answer vectors for the canonical `did:phi` derivation.

use phi_crypto::did::{did_from_public, Curve};

const R1_PK: &str = "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794";
const R1_DID: &str = "did:phi:1a3d5be062c4389f9a2c4097549d0c7f474a0176238b2f229475bd5842f1663f";

const K1_PK: &str = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
const K1_DID: &str = "did:phi:2580a99f69c809435c9ba44f68100a2970fa7fa5923d0fd9ca2befc537334244";

#[test]
fn kat_did_secp256r1() {
    let pk = hex::decode(R1_PK).expect("valid hex");
    assert_eq!(pk.len(), 65, "r1 canonical SEC1 is uncompressed");
    assert_eq!(did_from_public(Curve::Secp256r1, &pk).unwrap(), R1_DID);
}

#[test]
fn kat_did_secp256k1() {
    let pk = hex::decode(K1_PK).expect("valid hex");
    assert_eq!(pk.len(), 33, "k1 canonical SEC1 is compressed");
    assert_eq!(did_from_public(Curve::Secp256k1, &pk).unwrap(), K1_DID);
}
