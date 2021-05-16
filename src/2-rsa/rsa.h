/* DannyNiu/NJF, 2021-01-13. Public Domain. */

#ifndef MySuiteA_rsa_h
#define MySuiteA_rsa_h 1

#include "../mysuitea-common.h"

// The structure is intentionally designed not in specification order,
// this "array order" is intended to enable writing decryption/signing
// operation in a single loop.

typedef struct {
    // CRT decryption/signing needs only 3 modulus-sized working variables,
    // Key generation requires 4.
    uint32_t offset_w1, offset_w2, offset_w3, offset_w4;
    uint32_t count_primes_other;
    uint32_t offset_n, offset_e, offset_d;
    uint32_t offset_q, offset_dQ;
    uint32_t offset_p, offset_dP, offset_qInv;
} RSA_Private_Context_Base_t;

typedef struct {
    uint32_t offset_r, offset_d, offset_t;
} RSA_OtherPrimeInfo_t;

#define RSA_PRIVATE_CONTEXT_T(...)                      \
    struct {                                            \
        RSA_Private_Context_Base_t base;                \
        RSA_OtherPrimeInfo_t primes_other[__VA_ARGS__]; \
    }

typedef RSA_PRIVATE_CONTEXT_T() RSA_Private_Context_t;

typedef struct {
    uint32_t l; // modulus bits,
    uint32_t c; // number of primes.
} RSA_Private_Param_t;

// note-1:
// 32 * 3 - 1 because:
// see notes in "2-asn1/der-codec.c"
// ``ber_tlv_decode_integer''
//
// note-2:
// Assume sizeof(uint32_t) == 4.
#define RSA_PRIVATE_INTEGER_SIZE(bits) (4 * (((bits) + 32 * 3 - 1) / 32)))

// If c does not divide l, behavior is undefined.
#define RSA_PRIVATE_CONTEXT_SIZE(l,c) (                         \
        RSA_PRIVATE_INTEGER_SIZE((l) / (c)) * (3 * (c) - 1) +   \
        RSA_PRIVATE_INTEGER_SIZE((l)) * (2 + 4) +               \
        sizeof(RSA_Private_Context_Base_t) +                    \
        sizeof(RSA_OtherPrimeInfo_t) * ((c) - 2)  )

#define RSA_PRIVATE_PARAM_ENTUPLE(l_,c_)                \
    ((RSA_Private_Param_t){ .l = (l_), .c = (c_), })

#define RSA_PRIVATE_PARAM_DETUPLE(obj) (obj).l, (obj).c

// returns x on success and NULL on failure.

// If x is NULL, returns size estimate for its memory allocation;
// otherwise, returns x on success and 0 (NULL) on failure.
IntPtr rsa_keygen(
    RSA_Private_Context_t *restrict x,
    RSA_Private_Param_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

// 2021-05-15:
// ## Intended API usage: ##
//
// uint8_t rsa_priv_ctx[RSA_PRIVATE_CONTEXT_SIZE(2048,2)];
// RSA_Private_Param_t param_keygen = RSA_PRIVATE_PARAM_ENTUPLE(2048,2);
// rsa_keygen(&rsa_priv_ctx, *param_keygen, HMAC_DRBG_Generate, prng);
//
// ## or: ##
//
// RSA_Private_Param *param_keygen = ...;
// void *rsa_priv_ctx = malloc(rsa_keygen(NULL, &param_keygen, NULL, NULL));
// rsa_keygen(rsa_priv_ctx, param_keygen, SHAKE_Read, &xof);
//

#endif /* MySuiteA_rsa_h */
