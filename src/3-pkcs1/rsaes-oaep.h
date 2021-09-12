/* DannyNiu/NJF, 2021-09-10. Public Domain. */

#ifndef MySuiteA_RSAES_OAEP_h
#define MySuiteA_RSAES_OAEP_h 1

#include "pkcs1.h"

// returns x on success and NULL on failure.
void *RSAES_OAEP_Decode_Ciphertext(
    PKCS1_Private_Context_t *restrict x,
    void *restrict ct, size_t ctlen);

// returns x on success and NULL on failure.
// if ss is NULL, *sslen is set to its length.
void *RSAES_OAEP_Dec(
    PKCS1_Private_Context_t *restrict x,
    void *restrict ss, size_t *restrict sslen);

// returns ct on success and NULL on failure.
// if ct is NULL, *ctlen is set to its length.
void *RSAES_OAEP_Encode_Ciphertext(
    PKCS1_Public_Context_t *restrict x,
    void *restrict ct, size_t *ctlen);

// returns ss on success and NULL on failure.
// by convention, if ss is NULL, *sslen is set to its length.
// however, because RSA accepts arbitrary-length message as input,
// the RSA-OAEP encrypt call will not change its value.
void *RSAES_OAEP_Enc(
    PKCS1_Public_Context_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng);

#endif /* MySuiteA_RSAES_OAEP_h */
