/* Includes BOTH headers in one translation unit and references every symbol. */
#include "phi_crypto.h"
#include "phi_crypto_voting_snark.h"

int probe(void) {
    void *f[] = {
        (void *)&phi_verify_signature,
        (void *)&phi_webauthn_verify,
        (void *)&phi_bbs_verify_proof,
        (void *)&phi_bbs2023_verify_proof,
        (void *)&phi_compute_nullifier,
        (void *)&phi_semaphore_verify_vote,
        (void *)&phi_voting_verify_vote_v1,
    };
    return (int)(sizeof(f) / sizeof(f[0]));
}
