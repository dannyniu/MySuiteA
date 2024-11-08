/* DannyNiu/NJF, 2023-05-18. Public Domain. */

#ifndef MySuiteA_ecc_dss_sign_hedged_h
#define MySuiteA_ecc_dss_sign_hedged_h 1

#include "ecc-common.h"
#include "../2-prng/hmac-drbg.h"

// 2023-05-19:
// This is an implementation of the IETF Draft at:
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-det-sigs-with-noise/
// Being a draft, technical details are subject to change,
// and this feature is therefore UNTESTED AND EXPERIMENTAL.
//
// 2024-11-08:
// These signer drivers are intended *only* for passing validation tests.
// Providing PRNG parameter sets and associating them ECDSA instances had
// been considered, and dropped - for one, some hash support keying natively,
// thus making association structure complex; not to mention the current
// KMAC-DRBG is a transitional solution, as a PRNG built natively from
// permutations are preferred.
// The 2nd parameter was renamed to 'HRNG', where 'H' stands for
// hedged hashing. To differentiate the PRNG passed down to the signer
// and the RNG used that generates additional randomness, the additional
// randomness is designed to be passed from an explicit buffer parameter.
// An update had been introduced here to support the newly added
// incremental signing feature, even though these are all *only* for
// passing the validation tests.

void *ECC_Hedged_Sign(
    ECC_Hash_Ctx_Hdr_t *restrict x,
    hmac_drbg_t *restrict hrng,
    PKSignFunc_t signer,
    void const *restrict msg, size_t msglen,
    void const *restrict nonce, size_t nlen);

void *ECC_Hedged_IncSign_Final(
    ECC_Hash_Ctx_Hdr_t *restrict x,
    hmac_drbg_t *restrict hrng,
    PKIncSignFinalFunc_t signer,
    void const *restrict nonce, size_t nlen);

#endif /* MySuiteA_ecc_dss_sign_hedged_h */
