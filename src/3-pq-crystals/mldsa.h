/* DannyNiu/NJF, 2023-09-21. Public Domain. */

#ifndef MySuiteA_MLDSA_h
#define MySuiteA_MLDSA_h 1

// 2023-10-04:
// The draft FIPS-204-IPD contains a logical error in the
// ExpandMask subroutine making the currently specified
// scheme sub-optimal. Although this doesn't technically
// hamper interoperability, it makes it essentially
// impossible to have test vectors to verify the correctness
// of implementations. Therefore, the MySuiteA implementation
// of ML-DSA (a.k.a. Dilithium) is currently experimental.

#include "../2-pq-crystals/dilithium-aux.h"

typedef CryptoParam_t MLDSA_Param_t[2];

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:  4 * (32+16+16+256)
typedef struct {
    // seeds.
    uint8_t rho[32];
    uint8_t K[32];
    uint8_t tr[64];

    int32_t status; // refer to "2-rsa/pkcs1-padding.h".

    // parameters.
    int16_t k, l; // differs only to pad structure to a multiply of 16 bytes.
    int32_t tau, eta, omega; // derive beta from tau and eta.
    int32_t log2_gamma1, gamma2;

    // key components.
    uint32_t offset_Ahat; // k x l
    uint32_t offset_s1hat; // l
    uint32_t offset_s2hat; // k
    uint32_t offset_t1, offset_t0hat; // k

    // signature variables.
    uint32_t offset_yz; // l
    uint32_t offset_w; // k
    uint32_t offset_ck, offset_cl; // k & l resp.

    // scratch registers.
    uint8_t challenge[64]; // also reused as mu.
    module256_t c;
} MLDSA_Priv_Ctx_Hdr_t;

#define MLDSA_PRIV_CTX_SIZE_X(k,l) (                    \
        sizeof(MLDSA_Priv_Ctx_Hdr_t) +                  \
        sizeof(module256_t) * (k*l + k*5 + l*3) )

#define SIZEOF_MLDSA_PRIV_HDR sizeof(MLDSA_Priv_Ctx_Hdr_t)
#define OFFSET_FORMULA(expr) SIZEOF_MLDSA_PRIV_HDR + SIZEOF_M256 * (expr)

#define MLDSA_PRIV_CTX_SIZE(...) MLDSA_PRIV_CTX_SIZE_X(__VA_ARGS__)

#define MLDSA_PRIV_CTX_INIT_X(kp,lp)                                    \
    ((MLDSA_Priv_Ctx_Hdr_t){                                            \
        .k = kp, .l = lp,                                               \
        .tau   = (kp == 4 ? 39 : kp == 6 ? 49 : kp == 8 ? 60 : -1),     \
        .eta   = (kp == 4 ? 2  : kp == 6 ? 4  : kp == 8 ? 2  : -1),     \
        .omega = (kp == 4 ? 80 : kp == 6 ? 55 : kp == 8 ? 75 : -1),     \
        .log2_gamma1 = (                                                \
            kp == 4 ? 17 : kp == 6 ? 19 : kp == 8 ? 19 : -1),           \
        .gamma2 = (                                                     \
            kp == 4 ? (MLDSA_Q - 1) / 88 :                              \
            kp == 6 ? (MLDSA_Q - 1) / 32 :                              \
            kp == 8 ? (MLDSA_Q - 1) / 32 : -1),                         \
        .offset_Ahat  = OFFSET_FORMULA(0),                              \
        .offset_s1hat = OFFSET_FORMULA(kp*lp + kp*0 + lp*0),            \
        .offset_s2hat = OFFSET_FORMULA(kp*lp + kp*0 + lp*1),            \
        .offset_t1    = OFFSET_FORMULA(kp*lp + kp*1 + lp*1),            \
        .offset_t0hat = OFFSET_FORMULA(kp*lp + kp*2 + lp*1),            \
        .offset_yz    = OFFSET_FORMULA(kp*lp + kp*3 + lp*1),            \
        .offset_w     = OFFSET_FORMULA(kp*lp + kp*3 + lp*2),            \
        .offset_ck    = OFFSET_FORMULA(kp*lp + kp*4 + lp*2),            \
        .offset_cl    = OFFSET_FORMULA(kp*lp + kp*5 + lp*2),            \
    })

#define MLDSA_PRIV_CTX_INIT(...) MLDSA_PRIV_CTX_INIT_X(__VA_ARGS__)

#define MLDSA_PRIV_CTX_T(...)                           \
    union {                                             \
        MLDSA_Priv_Ctx_Hdr_t header;                    \
        uint8_t blob[MLDSA_PRIV_CTX_SIZE(__VA_ARGS__)]; \
    }

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:   4 * (48+12+512)
typedef struct {
    uint8_t rho[32];
    uint8_t w1app[32*7]; // scratch register. 6 is sufficent, 7 is for padding.
    uint8_t tr[64];
    uint8_t c_hash[64]; // from a component of signature actually.

    int32_t status; // refer to "2-rsa/pkcs1-padding.h".

    // parameters.
    int32_t k, l; // differs only to pad structure to a multiply of 16 bytes.
    int32_t tau, eta, omega; // derive beta from tau and eta.
    int32_t log2_gamma1, gamma2;

    // key components.
    uint32_t offset_Ahat; // k x l
    uint32_t offset_t1hat; // k

    // signature variables.
    uint32_t offset_z; // l
    uint32_t offset_h; // k

    // scratch registers.
    module256_t c, w;
} MLDSA_Pub_Ctx_Hdr_t;

#define MLDSA_PUB_CTX_SIZE_X(k,l) (                     \
        sizeof(MLDSA_Pub_Ctx_Hdr_t) +                   \
        sizeof(module256_t) * (k*l + k*2 + l*1) )

#define SIZEOF_MLDSA_PUB_HDR sizeof(MLDSA_Pub_Ctx_Hdr_t)
#define OFFSET_EXPR(expr) SIZEOF_MLDSA_PUB_HDR + SIZEOF_M256 * (expr)

#define MLDSA_PUB_CTX_SIZE(...) MLDSA_PUB_CTX_SIZE_X(__VA_ARGS__)

#define MLDSA_PUB_CTX_INIT_X(kp,lp)                                     \
    ((MLDSA_Pub_Ctx_Hdr_t){                                             \
        .k = kp, .l = lp,                                               \
        .tau   = (kp == 4 ? 39 : kp == 6 ? 49 : kp == 8 ? 60 : -1),     \
        .eta   = (kp == 4 ? 2  : kp == 6 ? 4  : kp == 8 ? 2  : -1),     \
        .omega = (kp == 4 ? 80 : kp == 6 ? 55 : kp == 8 ? 75 : -1),     \
        .log2_gamma1 = (                                                \
            kp == 4 ? 17 : kp == 6 ? 19 : kp == 8 ? 19 : -1),           \
        .gamma2 = (                                                     \
            kp == 4 ? (MLDSA_Q - 1) / 88 :                              \
            kp == 6 ? (MLDSA_Q - 1) / 32 :                              \
            kp == 8 ? (MLDSA_Q - 1) / 32 : -1),                         \
        .offset_Ahat  = OFFSET_EXPR(0),                                 \
        .offset_t1hat = OFFSET_EXPR(kp*lp + kp*0 + lp*0),               \
        .offset_z     = OFFSET_EXPR(kp*lp + kp*1 + lp*0),               \
        .offset_h     = OFFSET_EXPR(kp*lp + kp*1 + lp*1),               \
    })

#define MLDSA_PUB_CTX_INIT(...) MLDSA_PUB_CTX_INIT_X(__VA_ARGS__)

#define MLDSA_PUB_CTX_T(...)                            \
    union {                                             \
        MLDSA_Pub_Ctx_Hdr_t header;                     \
        uint8_t blob[MLDSA_PUB_CTX_SIZE(__VA_ARGS__)];  \
    }

IntPtr MLDSA_Keygen(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

IntPtr MLDSA_Encode_PrivateKey(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

IntPtr MLDSA_Decode_PrivateKey(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

IntPtr MLDSA_Export_PublicKey(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

IntPtr MLDSA_Encode_PublicKey(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

IntPtr MLDSA_Decode_PublicKey(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

void *MLDSA_Sign(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

void const *MLDSA_Verify(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen);

void *MLDSA_Encode_Signature(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen);

void *MLDSA_Decode_Signature(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict sig, size_t siglen);

#define xMLDSA_KeyCodec(q) (                                    \
        q==PKKeygenFunc ? (IntPtr)MLDSA_Keygen :                \
        q==PKPrivkeyEncoder ? (IntPtr)MLDSA_Encode_PrivateKey : \
        q==PKPrivkeyDecoder ? (IntPtr)MLDSA_Decode_PrivateKey : \
        q==PKPubkeyExporter ? (IntPtr)MLDSA_Export_PublicKey :  \
        q==PKPubkeyEncoder ? (IntPtr)MLDSA_Encode_PublicKey :   \
        q==PKPubkeyDecoder ? (IntPtr)MLDSA_Decode_PublicKey :   \
        0)

#define cMLDSA(k,l,q) (                                 \
        q==bytesCtxPriv ? MLDSA_PRIV_CTX_SIZE(k,l) :    \
        q==bytesCtxPub ? MLDSA_PUB_CTX_SIZE(k,l) :      \
        q==isParamDetermByKey ? false :                 \
        0)

#define xMLDSA(k,l,q) (                                 \
        q==PKKeygenFunc ? (IntPtr)MLDSA_Keygen :        \
        q==PKSignFunc ? (IntPtr)MLDSA_Sign :            \
        q==PKVerifyFunc ? (IntPtr)MLDSA_Verify :        \
        cMLDSA(k,l,q) )

#define xMLDSA_CtCodec(q) (                                     \
        q==PKSignFunc ? (IntPtr)MLDSA_Sign :                    \
        q==PKVerifyFunc ? (IntPtr)MLDSA_Verify :                \
        q==PKCtEncoder ? (IntPtr)MLDSA_Encode_Signature :       \
        q==PKCtDecoder ? (IntPtr)MLDSA_Decode_Signature :       \
        0)

IntPtr iMLDSA_KeyCodec(int q);
IntPtr tMLDSA(const CryptoParam_t *P, int q);
IntPtr iMLDSA_CtCodec(int q);

#endif /* MySuiteA_MLDSA_h */
