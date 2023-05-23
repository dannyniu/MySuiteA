/* DannyNiu/NJF, 2023-05-19. Public Domain. */

#ifndef MySuiteA_eddsa_sign_hedged_h
#define MySuiteA_eddsa_sign_hedged_h 1

#include "eddsa.h"

// 2023-05-19:
// See notes in "3-ecc-common/ecc-dss-sign-hedged.h".

void *EdDSA_Hedged_Sign(
    EdDSA_Ctx_Hdr_t *restrict x,
    void *restrict hash,
    PKSignFunc_t signer,
    void const *restrict msg, size_t msglen,
    void const *restrict nonce, size_t nlen);

#endif /* MySuiteA_eddsa_sign_hedged_h */
