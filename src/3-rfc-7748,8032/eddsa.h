/* DannyNiu/NJF, 2022-05-05. Public Domain. */

#ifndef MySuiteA_eddsa_h
#define MySuiteA_eddsa_h 1

#include "../2-ec/ecEd.h"
#include "../2-hash/hash-funcs-set.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4 *47 | 4 *48 | 8 *27
typedef struct {
    uint8_t sk[64];
    uint8_t prefix[64];

    uint32_t offset_s, offset_A; // private key scalar and public key.
    uint32_t offset_r, offset_R; // per-message keypair.

    uint32_t offset_Tmp1, offset_Tmp2;
    uint32_t offset_opctx;
    int16_t status, flags;

    ecEd_curve_t const *curve;
    size_t hashctx_size;
    uint32_t offset_hashctx;
    uint32_t offset_hashctx_init;

    hash_funcs_set_t hfuncs;
} EdDSA_Ctx_Hdr_t;

#define EdDSA_Flags_PH 1

typedef CryptoParam_t EdDSA_Param_t[2];

#define EDDSA_CTX_SIZE_X(crv,hash) (            \
        crv(ecEd_BytesOpCtx) +                  \
        crv(ecEd_BytesXYTZ) * 4 +               \
        crv(ecEd_BytesVLong) * 2 +              \
        hash(contextBytes) * 2 +                \
        sizeof(EdDSA_Ctx_Hdr_t) )

#define EDDSA_CTX_SIZE(...) EDDSA_CTX_SIZE_X(__VA_ARGS__)

#define EDDSA_CTX_INIT_X(crv,hash,...)                          \
    ((EdDSA_Ctx_Hdr_t){                                         \
        .curve = (const void *)crv(ecEd_PtrCurveDef),           \
        .status = 0,                                            \
        .flags = 0,                                             \
        .offset_hashctx = sizeof(EdDSA_Ctx_Hdr_t) +             \
        hash(contextBytes) * 0,                                 \
        .offset_hashctx_init = sizeof(EdDSA_Ctx_Hdr_t) +        \
        hash(contextBytes) * 1,                                 \
        .offset_opctx = sizeof(EdDSA_Ctx_Hdr_t) +               \
        hash(contextBytes) * 2,                                 \
        .offset_A     = sizeof(EdDSA_Ctx_Hdr_t) +               \
        hash(contextBytes) * 2 +                                \
        crv(ecEd_BytesOpCtx) +                                  \
        crv(ecEd_BytesXYTZ) * 0,                                \
        .offset_R     = sizeof(EdDSA_Ctx_Hdr_t) +               \
        hash(contextBytes) * 2 +                                \
        crv(ecEd_BytesOpCtx) +                                  \
        crv(ecEd_BytesXYTZ) * 1,                                \
        .offset_Tmp1  = sizeof(EdDSA_Ctx_Hdr_t) +               \
        hash(contextBytes) * 2 +                                \
        crv(ecEd_BytesOpCtx) +                                  \
        crv(ecEd_BytesXYTZ) * 2,                                \
        .offset_Tmp2  = sizeof(EdDSA_Ctx_Hdr_t) +               \
        hash(contextBytes) * 2 +                                \
        crv(ecEd_BytesOpCtx) +                                  \
        crv(ecEd_BytesXYTZ) * 3,                                \
        .offset_s     = sizeof(EdDSA_Ctx_Hdr_t) +               \
        hash(contextBytes) * 2 +                                \
        crv(ecEd_BytesOpCtx) +                                  \
        crv(ecEd_BytesXYTZ) * 4 +                               \
        crv(ecEd_BytesVLong) * 0,                               \
        .offset_r     = sizeof(EdDSA_Ctx_Hdr_t) +               \
        hash(contextBytes) * 2 +                                \
        crv(ecEd_BytesOpCtx) +                                  \
        crv(ecEd_BytesXYTZ) * 4 +                               \
        crv(ecEd_BytesVLong) * 1,                               \
        __VA_ARGS__                                             \
    })

#define EDDSA_CTX_T(...)                                \
    union {                                             \
        EdDSA_Ctx_Hdr_t header;                         \
        uint8_t blob[EDDSA_CTX_SIZE(__VA_ARGS__)];      \
    }

#define EDDSA_CTX_INIT(...) EDDSA_CTX_INIT_X(__VA_ARGS__)

IntPtr EdDSA_Keygen(
    EdDSA_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

IntPtr EdDSA_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr EdDSA_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

#define EdDSA_Export_PublicKey EdDSA_Encode_PublicKey

IntPtr EdDSA_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr EdDSA_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

void *EdDSA_Sign(
    EdDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

void const *EdDSA_Verify(
    EdDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen);

void *EdDSA_Encode_Signature(
    EdDSA_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen);

void *EdDSA_Decode_Signature(
    EdDSA_Ctx_Hdr_t *restrict x,
    void const *restrict sig, size_t siglen);

void *EdDSA_Sign_Xctrl(
    EdDSA_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

void *EdDSA_Verify_Xctrl(
    EdDSA_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

enum {
    EdDSA_cmd_null          = 0,

    // This command is used for setting pre-hash flag and context string.
    // bufvec[0].dat is reserved and should be NULL,
    // bufvec[0].info is the bitwise-or of EdDSA_Flags_* macro constants.
    // bufvec[1].dat is the pointer to context string,
    // bufvec[1].len is its length, and should be no greater than 255.
    EdDSA_set_domain_params = 1, // pre-hash flag and context.
};

int EdDSA_PKParams(int index, CryptoParam_t *out);

#define xEdDSA_KeyCodec(q) (                                    \
        q==PKKeygenFunc ? (IntPtr)EdDSA_Keygen :                \
        q==PKPrivkeyEncoder ? (IntPtr)EdDSA_Encode_PrivateKey : \
        q==PKPrivkeyDecoder ? (IntPtr)EdDSA_Decode_PrivateKey : \
        q==PKPubkeyExporter ? (IntPtr)EdDSA_Export_PublicKey :  \
        q==PKPubkeyEncoder ? (IntPtr)EdDSA_Encode_PublicKey :   \
        q==PKPubkeyDecoder ? (IntPtr)EdDSA_Decode_PublicKey :   \
        0)

#define cEdDSA(crv,hash,q) (                            \
        q==bytesCtxPriv ? EDDSA_CTX_SIZE(crv,hash) :      \
        q==bytesCtxPub ? EDDSA_CTX_SIZE(crv,hash) :       \
        q==isParamDetermByKey ? false :                 \
        0)

#define xEdDSA(crv,hash,q) (                            \
        q==PKParamsFunc ? (IntPtr)EdDSA_PKParams :      \
        q==PKKeygenFunc ? (IntPtr)EdDSA_Keygen :        \
        q==PKSignFunc ? (IntPtr)EdDSA_Sign :            \
        q==PKVerifyFunc ? (IntPtr)EdDSA_Verify :        \
        q==PubXctrlFunc ? (IntPtr)EdDSA_Verify_Xctrl : \
        q==PrivXctrlFunc ? (IntPtr)EdDSA_Sign_Xctrl :  \
        cEdDSA(crv,hash,q) )

#define xEdDSA_CtCodec(q) (                                     \
        q==PKSignFunc ? (IntPtr)EdDSA_Sign :                    \
        q==PKVerifyFunc ? (IntPtr)EdDSA_Verify :                \
        q==PKCtEncoder ? (IntPtr)EdDSA_Encode_Signature :       \
        q==PKCtDecoder ? (IntPtr)EdDSA_Decode_Signature :       \
        0)

IntPtr iEdDSA_KeyCodec(int q);
IntPtr tEdDSA(const CryptoParam_t *P, int q);
IntPtr iEdDSA_CtCodec(int q);

#endif /* MySuiteA_eddsa_h */
