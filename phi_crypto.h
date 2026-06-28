/*
 * phi_crypto.h — C-ABI header for the PHI cryptography core.
 *
 * Primary consumer: phi-chain (Go/cgo) for on-chain verification of signatures/WebAuthn/BBS+/nullifier.
 * Contract: every verification function returns `1` on success and `0` otherwise (safe default).
 * No panic crosses the boundary. Pointers are read-only (except the nullifier output buffer).
 *
 * Regenerate with: `cbindgen --config cbindgen.toml --output phi_crypto.h`.
 *
 * Use from Go:
 *   // #cgo LDFLAGS: -L./lib -lphi_crypto
 *   // #include "phi_crypto.h"
 *   import "C"
 *
 * (c) Homaan Smart Data Co. — Apache-2.0
 */
#ifndef PHI_CRYPTO_H
#define PHI_CRYPTO_H

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
 * Enforces type/challenge/origin/rpId/User-Presence/low-S. Returns: 1 valid, 0 otherwise. */
int32_t phi_webauthn_verify(const uint8_t *auth_data, uintptr_t auth_data_len,
                            const uint8_t *client_data_json, uintptr_t client_data_json_len,
                            const uint8_t *signature, uintptr_t signature_len,
                            const uint8_t *challenge, uintptr_t challenge_len,
                            const uint8_t *public_key, uintptr_t public_key_len,
                            const uint8_t *origin, uintptr_t origin_len,
                            const uint8_t *rp_id, uintptr_t rp_id_len);

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

/* Compute a nullifier; writes 32 bytes into out (pre-allocated by the caller).
 * Returns: 1 success, 0 bad input. */
int32_t phi_compute_nullifier(const uint8_t *secret, uintptr_t secret_len,
                              const uint8_t *topic, uintptr_t topic_len,
                              uint8_t *out);

/* Verify a BBS eligibility proof bound to (election_id, nullifier, signal) — Semaphore binding layer.
 * signal is the canonical encoding of the chosen option (binds the ballot choice; M8).
 * nullifier must be 32 bytes; a zero-length signal is permitted. Returns: 1 valid, 0 invalid/bad input. */
int32_t phi_semaphore_verify_vote(const uint8_t *bbs_proof, uintptr_t bbs_proof_len,
                                  const uint8_t *public_key, uintptr_t public_key_len,
                                  const uint8_t *election_id, uintptr_t election_id_len,
                                  const uint8_t *nullifier, uintptr_t nullifier_len,
                                  const uint8_t *signal, uintptr_t signal_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PHI_CRYPTO_H */
