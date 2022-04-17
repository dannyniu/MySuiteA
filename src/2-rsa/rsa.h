/* DannyNiu/NJF, 2021-01-13. Public Domain. */

#ifndef MySuiteA_rsa_h
#define MySuiteA_rsa_h 1

#include "../1-integers/vlong.h"

// -- For *ALL* working context data structures defined in this file --
// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:         4 * n       .

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
} RSA_Priv_Base_Ctx_t;

typedef struct {
    uint32_t offset_r, offset_d, offset_t;
} RSA_OtherPrimeInfo_t;

//
// RSA Private Context Header.

#define RSA_PRIV_CTX_HDR_T(...)                         \
    struct {                                            \
        RSA_Priv_Base_Ctx_t base;                       \
        RSA_OtherPrimeInfo_t primes_other[__VA_ARGS__]; \
    }

typedef RSA_PRIV_CTX_HDR_T() RSA_Priv_Ctx_Hdr_t;

// The value of ${ [0].aux } is the size of modulus in bits.
// The value of ${ [1].aux } is the number of primes.
typedef CryptoParam_t RSA_Priv_Param_t[2];

// [!A-E-D!]: If c does not divide l, behavior is undefined.
//
// 2021-09-11:
// The erroneous (2 + 4) is changed to (5 + 2).
// (2 * 4) changed to VLONG_BITS_SIZE(17)
//
// 2022-02-13:
// RSA_INTEGER_SIZE changed to VLONG_BITS_SIZE
#define RSA_PRIV_CTX_PAYLOAD_SIZE_X(l,c) (              \
        VLONG_BITS_SIZE((l) / (c)) * (3 * (c) - 1) +    \
        VLONG_BITS_SIZE((l)) * (5 + 2) +                \
        VLONG_BITS_SIZE(17) )

#define RSA_PRIV_CTX_PAYLOAD_SIZE(...)          \
    RSA_PRIV_CTX_PAYLOAD_SIZE_X(__VA_ARGS__)

#define RSA_PRIV_CTX_SIZE_X(l,c) (                      \
        RSA_PRIV_CTX_PAYLOAD_SIZE(l,c) +                \
        sizeof(RSA_Priv_Base_Ctx_t) +                   \
        sizeof(RSA_OtherPrimeInfo_t) * ((c) - 2) )

#define RSA_PRIV_CTX_SIZE(...)                  \
    RSA_PRIV_CTX_SIZE_X(__VA_ARGS__)

#define RSA_PRIV_CTX_T(l,c)                                     \
    struct {                                                    \
        RSA_PRIV_CTX_HDR_T(c) header;                           \
        uint8_t payload[RSA_PRIV_CTX_PAYLOAD_SIZE(l,c)];        \
    }

typedef struct {
    uint32_t offset_w1, offset_w2, offset_w3, offset_w4;
    uint32_t offset_n, offset_e, modulus_bits;
} RSA_Pub_Ctx_Hdr_t;

// The value of ${ [0].aux } is the size of modulus in bits.
typedef CryptoParam_t RSA_Pub_Param_t[1];

#define RSA_PUB_CTX_PAYLOAD_SIZE(l) (           \
        VLONG_BITS_SIZE((l)) * (4 + 1) +        \
        VLONG_BITS_SIZE(17) )

#define RSA_PUB_CTX_SIZE(l) (                   \
        RSA_PUB_CTX_PAYLOAD_SIZE(l) +           \
        sizeof(RSA_Pub_Ctx_Hdr_t) )

#define RSA_PUB_CTX_T(l)                                \
    struct {                                            \
        RSA_Pub_Ctx_Hdr_t header;                       \
        uint8_t payload[RSA_PUB_CTX_PAYLOAD_SIZE(l)];   \
    }

// If x is NULL, returns size estimate for its memory allocation;
// otherwise, returns x on success and 0 (NULL) on failure.
IntPtr rsa_keygen(
    RSA_Priv_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

// 2022-02-25: remove 1 obsolete note from 2021-05-15.
vlong_t *rsa_enc(RSA_Pub_Ctx_Hdr_t *restrict x);

vlong_t *rsa_fastdec(RSA_Priv_Ctx_Hdr_t *restrict x);

#endif /* MySuiteA_rsa_h */
