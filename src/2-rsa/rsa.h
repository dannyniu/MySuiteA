/* DannyNiu/NJF, 2021-01-13. Public Domain. */

#ifndef MySuiteA_rsa_h
#define MySuiteA_rsa_h 1

#include "../1-integers/vlong.h"

// The structure is intentionally designed not in specification order,
// this "array order" is intended to enable writing decryption/signing
// operation in a single loop.

// The CRT decryption/signing code assumes working variables w3 and w4
// can hold 3 factor-sized integers. It is further assumed that
// each factor will be at least 512 bits.

typedef struct {
    // CRT decryption/signing needs 3 modulus-sized and 3 factor-sized
    // vlongs. Key generation requires 4 modulus-sized vlongs.
    // It is guaranteed that the allocation of w1 thru w4 are contiguous,
    // although the placement of such contiguous region is undefined.
    uint32_t offset_w1, offset_w2, offset_w3, offset_w4, offset_w5;
    uint32_t count_primes_other, modulus_bits;
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
// 32 * 3 because:
// see notes in "2-asn1/der-codec.c"
// ``ber_tlv_decode_integer''
//
// note-2:
// Assume sizeof(uint32_t) == 4.
static_assert(sizeof(uint32_t) == 4, "Data type assumption failed");
#define RSA_INTEGER_SIZE(bits) (4 * (((bits) + 32 * 3) / 32))

// [!A-E-D!]: If c does not divide l, behavior is undefined.
//
// 2021-09-11:
// The erroneous (2 + 4) is changed to (5 + 2).
// (2 * 4) changed to RSA_INTEGER_SIZE(17)
#define RSA_PRIVATE_CONTEXT_SIZE_X(l,c) (               \
        RSA_INTEGER_SIZE((l) / (c)) * (3 * (c) - 1) +   \
        RSA_INTEGER_SIZE((l)) * (5 + 2) +               \
        RSA_INTEGER_SIZE(17) +                          \
        sizeof(RSA_Private_Context_Base_t) +            \
        sizeof(RSA_OtherPrimeInfo_t) * ((c) - 2)  )

#define RSA_PRIVATE_CONTEXT_SIZE(...)           \
    RSA_PRIVATE_CONTEXT_SIZE_X(__VA_ARGS__)

// the following macros are run-time only.
#define RSA_PRIVATE_PARAM_ENTUPLE(l_,c_)                \
    ((RSA_Private_Param_t){ .l = (l_), .c = (c_), })

#define RSA_PRIVATE_PARAM_DETUPLE(obj) (obj).l, (obj).c

typedef struct {
    uint32_t offset_w1, offset_w2, offset_w3, offset_w4;
    uint32_t offset_n, offset_e, modulus_bits;
} RSA_Public_Context_t;

#define RSA_PUBLIC_CONTEXT_SIZE(l) (            \
        RSA_INTEGER_SIZE((l)) * (4 + 1) +       \
        RSA_INTEGER_SIZE(17) +                  \
        sizeof(RSA_Public_Context_t) )

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

vlong_t *rsa_enc(RSA_Public_Context_t *restrict x);

vlong_t *rsa_fastdec(RSA_Private_Context_t *restrict x);

#endif /* MySuiteA_rsa_h */
