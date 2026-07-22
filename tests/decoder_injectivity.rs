// SPDX-License-Identifier: Apache-2.0
//! Injectivity of every byte decoder that crosses a trust boundary.

use phi_crypto::bbs::{self, CryptoSuite, DocknetBbsPlus, SelectiveProof, MAX_BBS_MESSAGES};

/// A canonical three-claim credential with two claims revealed, produced by the real prover — so every "canonical input round-trips" assertion is about a proof the library actually emits.
fn canonical_proof() -> (SelectiveProof, Vec<u8>) {
    let claims: Vec<Vec<u8>> = vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];
    let kp = DocknetBbsPlus::generate_keypair(claims.len() as u32).expect("keypair");
    let sig = DocknetBbsPlus::sign_credential(&claims, &kp.secret).expect("sign");
    let proof = DocknetBbsPlus::derive_proof(&claims, &sig, &[0, 2], b"nonce").expect("derive");
    let bytes = proof.to_bytes();
    (proof, bytes)
}

/// A canonical encoding round-trips, and the re-encoding is byte-identical — so the canonical form is a fixed point and there is exactly one encoding of an accepted proof.
#[test]
fn selective_proof_canonical_input_round_trips() {
    let (proof, bytes) = canonical_proof();

    let decoded = SelectiveProof::from_bytes(&bytes).expect("canonical bytes must decode");
    assert_eq!(decoded.message_count, proof.message_count);
    assert_eq!(decoded.proof, proof.proof);
    assert_eq!(decoded.revealed, proof.revealed);
    assert_eq!(
        decoded.to_bytes(),
        bytes,
        "re-encoding a decoded proof must reproduce the input exactly"
    );

    let kp_public_ok = bbs::verify_proof_bytes(&bytes, &[], b"nonce");
    assert!(!kp_public_ok, "an empty public key must not verify");
}

/// THE PoC.
#[test]
fn selective_proof_rejects_trailing_bytes() {
    let (_, bytes) = canonical_proof();
    assert!(SelectiveProof::from_bytes(&bytes).is_ok(), "precondition");

    for suffix in [
        vec![0x00],
        vec![0xff],
        vec![0x00; 32],
        b"appended".to_vec(),
        vec![0x41; 1024],
    ] {
        let mut padded = bytes.clone();
        padded.extend_from_slice(&suffix);
        assert!(
            SelectiveProof::from_bytes(&padded).is_err(),
            "a {}-byte suffix must be rejected, not silently ignored",
            suffix.len()
        );
    }
}

/// Truncation at every prefix length must fail rather than decode a partial proof.
#[test]
fn selective_proof_rejects_truncation() {
    let (_, bytes) = canonical_proof();
    for cut in 0..bytes.len() {
        assert!(
            SelectiveProof::from_bytes(&bytes[..cut]).is_err(),
            "a {cut}-byte prefix must not decode"
        );
    }
}

/// `message_count` is bounded on both ends: zero panics the backend's generator setup, and an oversized value would drive an unbounded generator allocation.
#[test]
fn selective_proof_rejects_an_out_of_range_message_count() {
    let encode_header = |count: u32| {
        let mut b = Vec::new();
        b.extend_from_slice(&count.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes()); // empty proof
        b.extend_from_slice(&0u32.to_be_bytes()); // no revealed claims
        b
    };

    assert!(SelectiveProof::from_bytes(&encode_header(0)).is_err());
    assert!(SelectiveProof::from_bytes(&encode_header(MAX_BBS_MESSAGES + 1)).is_err());
    assert!(SelectiveProof::from_bytes(&encode_header(u32::MAX)).is_err());
    assert!(SelectiveProof::from_bytes(&encode_header(MAX_BBS_MESSAGES)).is_ok());
    assert!(SelectiveProof::from_bytes(&encode_header(1)).is_ok());
}

/// Builds a `SelectiveProof` encoding with an arbitrary revealed list, bypassing `to_bytes` so the non-canonical forms below can be expressed at all.
fn encode_with_revealed(message_count: u32, revealed: &[(u32, &[u8])]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&message_count.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes()); // empty proof body: the decoder is what is under test
    b.extend_from_slice(&(revealed.len() as u32).to_be_bytes());
    for (idx, claim) in revealed {
        b.extend_from_slice(&idx.to_be_bytes());
        b.extend_from_slice(&(claim.len() as u32).to_be_bytes());
        b.extend_from_slice(claim);
    }
    b
}

/// Reordering and repetition are the two remaining ways to encode one revealed SET more than once.
#[test]
fn selective_proof_rejects_unsorted_and_duplicate_indices() {
    assert!(
        SelectiveProof::from_bytes(&encode_with_revealed(3, &[(0, b"a"), (2, b"c")])).is_ok(),
        "the canonical ascending form must be accepted"
    );

    assert!(
        SelectiveProof::from_bytes(&encode_with_revealed(3, &[(2, b"c"), (0, b"a")])).is_err(),
        "a reordered revealed list must be refused"
    );
    assert!(
        SelectiveProof::from_bytes(&encode_with_revealed(3, &[(0, b"a"), (0, b"b")])).is_err(),
        "a repeated index must be refused"
    );
    assert!(SelectiveProof::from_bytes(&encode_with_revealed(3, &[(1, b"x"), (1, b"x")])).is_err());
}

/// A revealed index outside the credential cannot name a claim, so it cannot be part of a meaningful proof; refusing it at decode keeps the decoded value consistent with `message_count`.
#[test]
fn selective_proof_rejects_an_out_of_range_revealed_index() {
    assert!(SelectiveProof::from_bytes(&encode_with_revealed(3, &[(3, b"a")])).is_err());
    assert!(SelectiveProof::from_bytes(&encode_with_revealed(3, &[(u32::MAX, b"a")])).is_err());
    assert!(SelectiveProof::from_bytes(&encode_with_revealed(3, &[(2, b"a")])).is_ok());
}

/// The revealed count cannot exceed the credential's claim count, which also bounds the capacity the decoder reserves before reading anything.
#[test]
fn selective_proof_rejects_a_revealed_count_over_message_count() {
    let mut b = Vec::new();
    b.extend_from_slice(&2u32.to_be_bytes()); // message_count = 2
    b.extend_from_slice(&0u32.to_be_bytes()); // empty proof
    b.extend_from_slice(&u32::MAX.to_be_bytes()); // hostile revealed count
    assert!(SelectiveProof::from_bytes(&b).is_err());
}

/// INJECTIVITY, stated directly: over a corpus of accepted encodings, distinct bytes always yield distinct proofs.
#[test]
fn selective_proof_decoding_is_injective() {
    let mut corpus: Vec<Vec<u8>> = Vec::new();
    for message_count in [1u32, 2, 3, MAX_BBS_MESSAGES] {
        corpus.push(encode_with_revealed(message_count, &[]));
        if message_count >= 1 {
            corpus.push(encode_with_revealed(message_count, &[(0, b"a")]));
            corpus.push(encode_with_revealed(message_count, &[(0, b"b")]));
        }
        if message_count >= 3 {
            corpus.push(encode_with_revealed(message_count, &[(0, b"a"), (2, b"c")]));
            corpus.push(encode_with_revealed(message_count, &[(1, b"a"), (2, b"c")]));
        }
    }
    let (_, real) = canonical_proof();
    corpus.push(real);

    let mut seen: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for bytes in &corpus {
        let decoded = SelectiveProof::from_bytes(bytes).expect("corpus entry must decode");
        let canonical = decoded.to_bytes();
        assert_eq!(
            &canonical, bytes,
            "an accepted encoding must already be the canonical one"
        );
        for (prev_bytes, prev_canonical) in &seen {
            if prev_bytes != bytes {
                assert_ne!(
                    prev_canonical, &canonical,
                    "distinct inputs decoded to the same proof"
                );
            }
        }
        seen.push((bytes.clone(), canonical));
    }
}

#[test]
fn structured_decoders_agree_on_canonical_form() {
    let (_, bytes) = canonical_proof();
    let decoded = SelectiveProof::from_bytes(&bytes).expect("decode");

    let mut padded = bytes.clone();
    padded.push(0);
    assert!(SelectiveProof::from_bytes(&padded).is_err());

    assert!(decoded.message_count > 0 && decoded.message_count <= MAX_BBS_MESSAGES);
    assert!(decoded.revealed.len() <= decoded.message_count as usize);

    for pair in decoded.revealed.windows(2) {
        assert!(
            pair[0].0 < pair[1].0,
            "an accepted proof must carry ascending revealed indices"
        );
    }
}
