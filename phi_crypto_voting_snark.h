/*
 * phi_crypto_voting_snark.h — C-ABI header for the PHI cryptography core, `voting_snark` build.
 *
 * This is the header for the feature-gated build (`--features voting_snark`). It is the default
 * `phi_crypto.h` PLUS the one additive, versioned export `phi_voting_verify_vote_v1`, which exists
 * ONLY when that feature is enabled. The default `phi_crypto.h` stays byte-identical and is what the
 * shipped, fail-closed staticlib exposes; consume this header only when linking the tagged build.
 *
 * Regenerate (with cbindgen available) by enabling the feature so the gated export is emitted:
 *   `cbindgen --config cbindgen-voting-snark.toml --output phi_crypto_voting_snark.h`
 *   # crate built with --features voting_snark
 *
 * This header carries its OWN include guard (PHI_CRYPTO_VOTING_SNARK_H). The two headers declare
 * overlapping symbol sets, so a shared guard would make whichever is included second expand to
 * nothing — a translation unit that included the default header first would then be missing the
 * gated declaration below, with no diagnostic pointing at the cause.
 * With the feature OFF, the same command reproduces `phi_crypto.h` byte-for-byte (the export is
 * `#[cfg(feature = "voting_snark")]`, so it is absent from the default C-ABI surface).
 *
 * Contract: every verification function returns `1` on success and `0` otherwise (safe default).
 * No panic crosses the boundary. Pointers are read-only (except the nullifier output buffer).
 *
 * Use from Go:
 *   // #cgo LDFLAGS: -L./lib -lphi_crypto
 *   // #include "phi_crypto.h"
 *   import "C"
 *
 * (c) Homaan Smart Data Co. — Apache-2.0
 */
#ifndef PHI_CRYPTO_VOTING_SNARK_H
#define PHI_CRYPTO_VOTING_SNARK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Verify an ECDSA signature. curve_code: 0 = secp256k1, 1 = secp256r1.
 * Returns: 1 valid, 0 invalid/bad input. */
int32_t phi_verify_signature(uint8_t curve_code,
                             const uint8_t *public_key, uintptr_t public_key_len,
                             const uint8_t *msg, uintptr_t msg_len,
                             const uint8_t *sig, uintptr_t sig_len);

/* Verify a WebAuthn assertion (P-256) over authData || SHA256(clientDataJSON).
 * Enforces type/challenge/origin/rpId/User-Presence/low-S. require_uv != 0 additionally demands the
 * User-Verification flag (biometric/PIN gesture), which sensitive operations require.
 * Returns: 1 valid, 0 otherwise. */
int32_t phi_webauthn_verify(const uint8_t *auth_data, uintptr_t auth_data_len,
                            const uint8_t *client_data_json, uintptr_t client_data_json_len,
                            const uint8_t *signature, uintptr_t signature_len,
                            const uint8_t *challenge, uintptr_t challenge_len,
                            const uint8_t *public_key, uintptr_t public_key_len,
                            const uint8_t *origin, uintptr_t origin_len,
                            const uint8_t *rp_id, uintptr_t rp_id_len,
                            int32_t require_uv);

/* Verify a BBS+ selective-disclosure proof (proof = serialized SelectiveProof bytes).
 * Returns: 1 valid, 0 otherwise. */
int32_t phi_bbs_verify_proof(const uint8_t *proof, uintptr_t proof_len,
                             const uint8_t *public_key, uintptr_t public_key_len,
                             const uint8_t *nonce, uintptr_t nonce_len);

/* Verify a W3C bbs-2023 selective-disclosure proof (BLS12-381 SHA-256). revealed = length-prefixed
 * encoding of (index,value) pairs. Returns: 1 valid, 0 otherwise. Native targets only. */
int32_t phi_bbs2023_verify_proof(const uint8_t *proof, uintptr_t proof_len,
                                 const uint8_t *public_key, uintptr_t public_key_len,
                                 const uint8_t *header, uintptr_t header_len,
                                 const uint8_t *presentation_header, uintptr_t presentation_header_len,
                                 const uint8_t *revealed, uintptr_t revealed_len);

/* Compute a nullifier; writes 32 bytes into out. out_len states out's capacity so the write is
 * bounds-checked: if out is null or out_len < 32, nothing is written.
 * Returns: 1 success, 0 bad input (including an undersized output buffer). */
int32_t phi_compute_nullifier(const uint8_t *secret, uintptr_t secret_len,
                              const uint8_t *topic, uintptr_t topic_len,
                              uint8_t *out, uintptr_t out_len);

/* Verify a BBS eligibility proof bound to (election_id, nullifier, signal) — Semaphore binding layer.
 * signal is the canonical encoding of the chosen option (binds the ballot choice).
 * nullifier must be 32 bytes; a zero-length signal is permitted. Returns: 1 valid, 0 invalid/bad input. */
int32_t phi_semaphore_verify_vote(const uint8_t *bbs_proof, uintptr_t bbs_proof_len,
                                  const uint8_t *public_key, uintptr_t public_key_len,
                                  const uint8_t *election_id, uintptr_t election_id_len,
                                  const uint8_t *nullifier, uintptr_t nullifier_len,
                                  const uint8_t *signal, uintptr_t signal_len);

/* voting_snark builds only. Verify a composed anonymous-vote proof: BBS+ eligibility, the algebraic
 * derivation N = H_e^{m0}, the witness-equality binding m0 to the credential's signed voter-secret
 * message, and the (chain_id, election_id, N, signal) ballot binding — all at once. Unlike
 * phi_semaphore_verify_vote, accepting this means one-credential-one-nullifier-per-election.
 * proof is the serialized VoteProof blob (it carries N internally); chain_id is the network identifier
 * the proof was produced for (a proof made for a different network fails, blocking cross-network
 * ballot replay); nullifier is the caller's dedup key and MUST equal the 48-byte compressed G1
 * nullifier bound in the proof; a zero-length signal is permitted. Returns: 1 valid, 0 invalid/bad
 * input. */
int32_t phi_voting_verify_vote_v1(const uint8_t *proof, uintptr_t proof_len,
                                  const uint8_t *public_key, uintptr_t public_key_len,
                                  const uint8_t *chain_id, uintptr_t chain_id_len,
                                  const uint8_t *election_id, uintptr_t election_id_len,
                                  const uint8_t *nullifier, uintptr_t nullifier_len,
                                  const uint8_t *signal, uintptr_t signal_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PHI_CRYPTO_VOTING_SNARK_H */
