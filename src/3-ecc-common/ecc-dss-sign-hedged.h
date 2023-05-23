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

void *ECC_Hedged_Sign(
    ECC_Hash_Ctx_Hdr_t *restrict x,
    hmac_drbg_t *restrict prng,
    PKSignFunc_t signer,
    void const *restrict msg, size_t msglen,
    void const *restrict nonce, size_t nlen);

#endif /* MySuiteA_ecc_dss_sign_hedged_h */
