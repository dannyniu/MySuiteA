/* DannyNiu/NJF, 2021-09-10. Public Domain. */

#ifndef MySuiteA_RSASSA_PSS_h
#define MySuiteA_RSASSA_PSS_h 1

#include "pkcs1.h"

// returns sig on success and NULL on failure.
// if sig is NULL, *siglen is set to its length.
void *RSASSA_PSS_Encode_Signature(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen);

// returns x on success and NULL on failure.
void *RSASSA_PSS_Sign(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

// returns x on success and NULL on failure.
void *RSASSA_PSS_Decode_Signature(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t siglen);

// returns msg on success and NULL on failure.
void const *RSASSA_PSS_Verify(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen);

#endif /* MySuiteA_RSASSA_PSS_h */
