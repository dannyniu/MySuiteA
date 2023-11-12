/* DannyNiu/NJF, 2023-11-05. Public Domain. */

#ifndef MySuiteA_SLHDSA_h
#define MySuiteA_SLHDSA_h 1

#include "sphincs-hash-params-family.h"

// [0]: n
// [1]: h
// [2]: Hmsg
// [3]: PRF
// [4]: PRFmsg
// [5]: F
// [6]: H
// [7]: T
// All above are in ``[].aux''.
typedef CryptoParam_t SLHDSA_Param_t[8];

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4 *23 | 4 *26 | 8*16
typedef struct {
    uint32_t n, d, h, hapos;
    uint32_t a, k, lgw, m;

    struct {
        uint32_t w, len1, len2, len;
    } wots;

    SPHINCS_HashParam_t Hmsg, PRF, PRFmsg, F, H, T;
    uint32_t offset_buf_n_bytes;
    uint32_t offset_buf_n_wotslen_bytes;
    uint32_t offset_buf_n_hapos_p1_bytes;
    uint32_t offset_buf_n_k_bytes;
    uint32_t offset_buf_n_a_p1_bytes;
    uint32_t offset_signature;

    // struct { uint8_t SKseed[n], SKprf[n], PKseed[n], PKroot[n]; },
    // private key working contexts has all 4,
    // public key working context ignores the previous 2.
    uint32_t offset_key_elems;

    int32_t status;
} SLHDSA_Ctx_Hdr_t;

#define SLHDSA_SIG_BYTES(n, h, d, a, k)         \
    (n * (1 + k*(a + 1) + h + d*(n * 2 + 3)))

#define SLHDSA_BUF_BYTES(n, hapos, a, k)        \
    (n * (1 + n*2+3 + hapos + a+1 + k))

#define SLHDSA_PRIV_KEY_BYTES(n) (n * 4)

#define SLHDSA_MEM_DYN_BYTES(n, h, d, hapos, a, k)      \
    ( SLHDSA_SIG_BYTES(n, h, d, a, k) +                 \
      SLHDSA_BUF_BYTES(n, hapos, a, k) +                \
      SLHDSA_PRIV_KEY_BYTES(n) )

#define SLHDSA_CTX_SIZE_X(n, h)                                         \
    (sizeof(SLHDSA_Ctx_Hdr_t) + (                                       \
        n*100+h == 1663 ? SLHDSA_MEM_DYN_BYTES(16, 63, 7, 9, 12, 14) :  \
        n*100+h == 1666 ? SLHDSA_MEM_DYN_BYTES(16, 66, 22, 3, 6, 33) :  \
        n*100+h == 2463 ? SLHDSA_MEM_DYN_BYTES(24, 63, 7, 9, 14, 17) :  \
        n*100+h == 2466 ? SLHDSA_MEM_DYN_BYTES(24, 66, 22, 3, 8, 33) :  \
        n*100+h == 3264 ? SLHDSA_MEM_DYN_BYTES(32, 64, 8, 8, 14, 22) :  \
        n*100+h == 3268 ? SLHDSA_MEM_DYN_BYTES(32, 68, 17, 4, 9, 35) :  \
        -1 ))

#define SLHDSA_CTX_SIZE(...) SLHDSA_CTX_SIZE_X(__VA_ARGS__)

#define SLHDSA_CTX_INIT_HASHES_X(argHmsg, argPRF, argPRFmsg, argF, argH, argT) \
    .Hmsg = (SPHINCS_HashParam_t)argHmsg,                               \
        .PRF = (SPHINCS_HashParam_t)argPRF,                             \
        .PRFmsg = (SPHINCS_HashParam_t)argPRFmsg,                       \
        .F = (SPHINCS_HashParam_t)argF,                                 \
        .H = (SPHINCS_HashParam_t)argH,                                 \
        .T = (SPHINCS_HashParam_t)argT

#define SLHDSA_CTX_INIT_HASHES(...) SLHDSA_CTX_INIT_HASHES_X(__VA_ARGS__)

#define SLHDSA_CTX_INIT_VERBOSE(np, hp, dp, ap, kp, lgwp, mp, ...)      \
    ((SLHDSA_Ctx_Hdr_t){                                                \
        .n = np, .h = hp, .d = dp, .hapos = (hp/dp),                    \
        .a = ap, .k = kp, .m = mp, .lgw = 4,                            \
        .wots.w = 16, .wots.len = (2*np+3),                             \
        .wots.len1 = (2*np), .wots.len2 = 3,                            \
        .offset_buf_n_bytes          = sizeof(SLHDSA_Ctx_Hdr_t),        \
        .offset_buf_n_wotslen_bytes  = sizeof(SLHDSA_Ctx_Hdr_t) +       \
        np,                                                             \
        .offset_buf_n_hapos_p1_bytes = sizeof(SLHDSA_Ctx_Hdr_t) +       \
        np * (1 + 2*np+3),                                              \
        .offset_buf_n_k_bytes        = sizeof(SLHDSA_Ctx_Hdr_t) +       \
        np * (1 + 2*np+3 + (hp/dp)+1),                                  \
        .offset_buf_n_a_p1_bytes     = sizeof(SLHDSA_Ctx_Hdr_t) +       \
        np * (1 + 2*np+3 + (hp/dp)+1 + kp),                             \
        .offset_signature            = sizeof(SLHDSA_Ctx_Hdr_t) +       \
        np * (1 + 2*np+3 + (hp/dp)+1 + kp + ap+1),                      \
        .offset_key_elems            = sizeof(SLHDSA_Ctx_Hdr_t) +       \
        np * (1 + 2*np+3 + (hp/dp)+1 + kp + ap+1) +                     \
        SLHDSA_SIG_BYTES(np, hp, dp, ap, kp),                           \
        SLHDSA_CTX_INIT_HASHES(__VA_ARGS__),                            \
    })

#define SLHDSA_CTX_INIT_X(np, hp, ...)                                  \
    (np*100+hp == 1663 ?                                                \
     SLHDSA_CTX_INIT_VERBOSE(16, 63, 7, 12, 14, 4, 30, __VA_ARGS__) :   \
     np*100+hp == 1666 ?                                                \
     SLHDSA_CTX_INIT_VERBOSE(16, 66, 22, 6, 33, 4, 34, __VA_ARGS__) :   \
     np*100+hp == 2463 ?                                                \
     SLHDSA_CTX_INIT_VERBOSE(24, 63, 7, 14, 17, 4, 39, __VA_ARGS__) :   \
     np*100+hp == 2466 ?                                                \
     SLHDSA_CTX_INIT_VERBOSE(24, 66, 22, 8, 33, 4, 42, __VA_ARGS__) :   \
     np*100+hp == 3264 ?                                                \
     SLHDSA_CTX_INIT_VERBOSE(32, 64, 8, 14, 22, 4, 47, __VA_ARGS__) :   \
     np*100+hp == 3268 ?                                                \
     SLHDSA_CTX_INIT_VERBOSE(32, 68, 17, 9, 35, 4, 49, __VA_ARGS__) :   \
     SLHDSA_CTX_INIT_VERBOSE(-1, -1, -1, -1, -1, -1, -1, __VA_ARGS__))

#define SLHDSA_CTX_INIT(...) SLHDSA_CTX_INIT_X(__VA_ARGS__)

#define SLHDSA_CTX_T(...)                               \
    union {                                             \
        SLHDSA_Ctx_Hdr_t header;                        \
        uint8_t blob[SLHDSA_CTX_SIZE(__VA_ARGS__)];     \
    }

IntPtr SLHDSA_Keygen(
    SLHDSA_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

IntPtr SLHDSA_Encode_PrivateKey(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

IntPtr SLHDSA_Decode_PrivateKey(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

IntPtr SLHDSA_Encode_PublicKey(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

#define SLHDSA_Export_PublicKey SLHDSA_Encode_PublicKey

IntPtr SLHDSA_Decode_PublicKey(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

void *SLHDSA_Sign(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

void *SLHDSA_Encode_Signature(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen);

void *SLHDSA_Decode_Signature(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t siglen);

void const *SLHDSA_Verify(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen);

#define xSLHDSA_KeyCodec(q) (                                    \
        q==PKKeygenFunc ? (IntPtr)SLHDSA_Keygen :                \
        q==PKPrivkeyEncoder ? (IntPtr)SLHDSA_Encode_PrivateKey : \
        q==PKPrivkeyDecoder ? (IntPtr)SLHDSA_Decode_PrivateKey : \
        q==PKPubkeyExporter ? (IntPtr)SLHDSA_Export_PublicKey :  \
        q==PKPubkeyEncoder ? (IntPtr)SLHDSA_Encode_PublicKey :   \
        q==PKPubkeyDecoder ? (IntPtr)SLHDSA_Decode_PublicKey :   \
        0)

#define cSLHDSA(n,h,q) (                        \
        q==bytesCtxPriv || q==bytesCtxPub ?     \
        SLHDSA_CTX_SIZE(n,h) :                  \
        q==isParamDetermByKey ? false :         \
        0)

#define xSLHDSA(n,h,q) (                                 \
        q==PKKeygenFunc ? (IntPtr)SLHDSA_Keygen :        \
        q==PKSignFunc ? (IntPtr)SLHDSA_Sign :            \
        q==PKVerifyFunc ? (IntPtr)SLHDSA_Verify :        \
        cSLHDSA(n,h,q) )

#define xSLHDSA_CtCodec(q) (                                     \
        q==PKSignFunc ? (IntPtr)SLHDSA_Sign :                    \
        q==PKVerifyFunc ? (IntPtr)SLHDSA_Verify :                \
        q==PKCtEncoder ? (IntPtr)SLHDSA_Encode_Signature :       \
        q==PKCtDecoder ? (IntPtr)SLHDSA_Decode_Signature :       \
        0)

IntPtr iSLHDSA_KeyCodec(int q);
IntPtr tSLHDSA(const CryptoParam_t *P, int q);
IntPtr iSLHDSA_CtCodec(int q);

#endif /* MySuiteA_SLHDSA_h */
