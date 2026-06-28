# bbs-2023 (BLS12-381 SHA-256) test vectors — provenance

These known-answer vectors are the official `bbs-2023` fixtures for the
`BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_` ciphersuite, used to prove byte-for-byte
interoperability of the `bbs_2023` module with the IETF/W3C standard.

- **Source:** `mattrglobal/pairing_crypto`, tag `v0.4.4` (commit `3228ba6`),
  `tests/fixtures/bbs/bls12_381_sha_256/{signature,proof}`.
- **Upstream of the source:** the IETF draft `draft-irtf-cfrg-bbs-signatures` fixtures and the
  W3C `vc-di-bbs` `bbs-2023` cryptosuite.
- **License:** Apache-2.0 (same as `pairing_crypto`; see the crate `LICENSE`).

`signature/*.json` drive deterministic byte-exact sign + verify checks; `proof/*.json` drive
proof verification. Consumed by `tests/bbs_2023_kat.rs`.
