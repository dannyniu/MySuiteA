/* DannyNiu/NJF, 2023-10-24. Public Domain. */

#ifndef MySuiteA_MLKEM_h
#define MySuiteA_MLKEM_h 1

#include "../2-pq-crystals/kyber-aux.h"

typedef CryptoParam_t MLKEM_Param_t[1];

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:  4 * (32+16+10+256)
typedef struct {
    // data blobs.
    uint8_t z[32]; // For use in implicit rejection.
    uint8_t rho[32]; // To derive A^hat.
    uint8_t Hek[32]; // hash of the encapsulation key.

    // - during encapsulation:
    //   sampled 32-byte 'm' at first,
    //   shared secret when finish;
    // - during decapsulation:
    //   rejection key when load,
    //   shared secret after dec.
    uint8_t ss[32];

    // Enc: (K,R) <- G(m||H(ek)),
    // Dec: (K',r') <- G(m'||h).
    uint8_t tup[64];

    int32_t status; // refer to "2-rsa/pkcs1-padding.h".

    // parameters.
    int32_t k;
    int32_t eta1, eta2;
    int32_t du, dv;

    // key components.
    uint32_t offset_Ahat; // k x k.
    uint32_t offset_that; // k.
    uint32_t offset_shat; // k.

    // scratch registers.
    // - none needed.

    // ciphertext variables.
    uint32_t offset_u; // k. for u in encryption.
    module256_t vw; // for v in encryption and decryption, and w in decryption.
} MLKEM_Ctx_Hdr_t;

// ML-KEM, a.k.a. Kyber, runs encryption subroutine during decapsulation
// as part of ciphertext verification to achieve IND-CCA security. So it's
// necessary to make it possible to run encryption algorithm in a decryption
// working context. That's why the two contexts are one.
typedef MLKEM_Ctx_Hdr_t MLKEM_Priv_Ctx_Hdr_t, MLKEM_Pub_Ctx_hdr_t;

#define MLKEM_CTX_SIZE_X(k) (                   \
        sizeof(MLKEM_Ctx_Hdr_t) +               \
        sizeof(module256_t) * (k*k + 3*k) )

#define MLKEM_CTX_SIZE(...) MLKEM_CTX_SIZE_X(__VA_ARGS__)

#define OFFSET_EXPR(expr) sizeof(MLKEM_Ctx_Hdr_t) + SIZEOF_M256 * (expr)

#define MLKEM_CTX_INIT_X(kp)                                    \
    ((MLKEM_Ctx_Hdr_t){                                         \
        .k = kp,                                                \
        .eta1 = (kp == 2 ? 3 : kp == 3 || kp == 4 ? 2 : -1),    \
        .eta2 = 2,                                              \
        .du = (kp == 2 || kp == 3 ? 10 : kp == 4 ? 11 : -1),    \
        .dv = (kp == 2 || kp == 3 ? 4 : kp == 4 ? 5 : -1),      \
        .offset_Ahat = OFFSET_EXPR(0),                          \
        .offset_that = OFFSET_EXPR(kp*kp + kp*0),               \
        .offset_shat = OFFSET_EXPR(kp*kp + kp*1),               \
        .offset_u    = OFFSET_EXPR(kp*kp + kp*2),               \
    })

#define MLKEM_CTX_INIT(...) MLKEM_CTX_INIT_X(__VA_ARGS__)

#define MLKEM_CTX_T(...)                                \
    union {                                             \
        MLKEM_Ctx_Hdr_t header;                         \
        uint8_t blob[MLKEM_CTX_SIZE(__VA_ARGS__)];      \
    }

#define MLKEM_PRIV_CTX_SIZE MLKEM_CTX_SIZE
#define MLKEM_PRIV_CTX_INIT MLKEM_CTX_INIT
#define MLKEM_PRIV_CTX_T MLKEM_CTX_T

#define MLKEM_PUB_CTX_SIZE MLKEM_CTX_SIZE
#define MLKEM_PUB_CTX_INIT MLKEM_CTX_INIT
#define MLKEM_PUB_CTX_T MLKEM_CTX_T

IntPtr MLKEM_Keygen(
    MLKEM_Ctx_Hdr_t *restrict x, CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

IntPtr MLKEM_Encode_PrivateKey(
    MLKEM_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

IntPtr MLKEM_Decode_PrivateKey(
    MLKEM_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

void *MLKEM_Dec(
    MLKEM_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen);

void *MLKEM_Decode_Ciphertext(
    MLKEM_Ctx_Hdr_t *restrict x,
    void const *restrict ct, size_t ctlen);

void *MLKEM_Encode_Ciphertext(
    MLKEM_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t *ctlen);

IntPtr MLKEM_Encode_PublicKey(
    MLKEM_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

#define MLKEM_Export_PublicKey MLKEM_Encode_PublicKey

IntPtr MLKEM_Decode_PublicKey(
    MLKEM_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

void *MLKEM_Enc(
    MLKEM_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng);

#define xMLKEM_KeyCodec(q) (                                         \
        q==PKKeygenFunc ? (IntPtr)MLKEM_Keygen :                     \
        q==PKPrivkeyEncoder ? (IntPtr)MLKEM_Encode_PrivateKey :      \
        q==PKPrivkeyDecoder ? (IntPtr)MLKEM_Decode_PrivateKey :      \
        q==PKPubkeyExporter ? (IntPtr)MLKEM_Export_PublicKey :       \
        q==PKPubkeyEncoder ? (IntPtr)MLKEM_Encode_PublicKey :        \
        q==PKPubkeyDecoder ? (IntPtr)MLKEM_Decode_PublicKey :        \
        0)

#define cMLKEM(kp,q) (                          \
        q==bytesCtxPriv ? MLKEM_CTX_SIZE(kp) :  \
        q==bytesCtxPub ? MLKEM_CTX_SIZE(kp) :   \
        q==isParamDetermByKey ? false :         \
        0)

#define xMLKEM(kp,q) (                                  \
        q==PKKeygenFunc ? (IntPtr)MLKEM_Keygen :        \
        q==PKEncFunc ? (IntPtr)MLKEM_Enc :              \
        q==PKDecFunc ? (IntPtr)MLKEM_Dec :              \
        cMLKEM(kp,q) )

#define xMLKEM_CtCodec(q) (                                     \
        q==PKEncFunc ? (IntPtr)MLKEM_Enc :                      \
        q==PKDecFunc ? (IntPtr)MLKEM_Dec :                      \
        q==PKCtEncoder ? (IntPtr)MLKEM_Encode_Ciphertext :      \
        q==PKCtDecoder ? (IntPtr)MLKEM_Decode_Ciphertext :      \
        0)

IntPtr iMLKEM_KeyCodec(int q);
IntPtr tMLKEM(const CryptoParam_t *P, int q);
IntPtr iMLKEM_CtCodec(int q);

#endif /* MySuiteA_MLKEM_h */
