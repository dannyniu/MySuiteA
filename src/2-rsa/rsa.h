/* DannyNiu/NJF, 2021-01-13. Public Domain. */

#ifndef MySuiteA_rsa_h
#define MySuiteA_rsa_h 1

#include "../mysuitea-common.h"

// The structure is intentionally designed not in specification order,
// this "array order" is intended to enable writing decryption/signing
// operation in a single loop.

typedef struct {
    /* --TODO: add working variables here-- */
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

#endif /* MySuiteA_rsa_h */
