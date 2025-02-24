/* DannyNiu/NJF, 2022-04-16. Public Domain. */

#ifndef MySuiteA_sm2sig_h
#define MySuiteA_sm2sig_h 1

#include "../3-ecc-common/ecc-common.h"
#include "../2-hash/hash-funcs-set.h"

// ${ [0].* } are that for curve domain parameters.
// ${ [1].* } are that for the hash function.
typedef CryptoParam_t SM2SIG_Param_t[2];

typedef ECC_Hash_Ctx_Hdr_t SM2SIG_Ctx_Hdr_t;

#define SM2SIG_CTX_INIT_X(crv,hash) ECC_CTX_INIT_X(     \
        SM2SIG_Ctx_Hdr_t,                               \
        crv, hash,                                      \
        .hlen = OUT_BYTES(hash),                        \
        .hfuncs = HASH_FUNCS_SET_INIT(hash),            \
        .context_type = 2,                              \
        .offset_hashctx = sizeof(SM2SIG_Ctx_Hdr_t))

#define SM2SIG_CTX_INIT(...) SM2SIG_CTX_INIT_X(__VA_ARGS__)

IntPtr SM2SIG_Keygen(
    SM2SIG_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

IntPtr SM2SIG_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr SM2SIG_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr SM2SIG_Export_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr SM2SIG_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr SM2SIG_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

void *SM2SIG_Sign(
    SM2SIG_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

void const *SM2SIG_Verify(
    SM2SIG_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen);

void *SM2SIG_IncSign_Init(
    SM2SIG_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback);

void *SM2SIG_IncSign_Final(
    SM2SIG_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen,
    void *restrict prng);

void *SM2SIG_IncVerify_Init(
    SM2SIG_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback);

void *SM2SIG_IncVerify_Final(
    SM2SIG_Ctx_Hdr_t *restrict x);

void *SM2SIG_Encode_Signature(
    SM2SIG_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen);

void *SM2SIG_Decode_Signature(
    SM2SIG_Ctx_Hdr_t *restrict x,
    void const *restrict sig, size_t siglen);

void *SM2SIG_Sign_Xctrl(
    SM2SIG_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

void *SM2SIG_Verify_Xctrl(
    SM2SIG_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

enum {
    SM2SIG_cmd_null         = 0,
    SM2SIG_set_signer_id    = 1,
};

#define xSM2SIG_KeyCodec(q) (                                           \
        q==PKKeygenFunc ? (IntPtr)SM2SIG_Keygen :                       \
        q==PKPrivkeyEncoder ? (IntPtr)SM2SIG_Encode_PrivateKey :        \
        q==PKPrivkeyDecoder ? (IntPtr)SM2SIG_Decode_PrivateKey :        \
        q==PKPubkeyExporter ? (IntPtr)SM2SIG_Export_PublicKey :         \
        q==PKPubkeyEncoder ? (IntPtr)SM2SIG_Encode_PublicKey :          \
        q==PKPubkeyDecoder ? (IntPtr)SM2SIG_Decode_PublicKey :          \
        0)

#define cSM2SIG(crv,hash,q) (                                   \
        q==bytesCtxPriv ? (IntPtr)ECC_CTX_SIZE(crv,hash) :      \
        q==bytesCtxPub ? (IntPtr)ECC_CTX_SIZE(crv,hash) :       \
        q==isParamDetermByKey ? false :                         \
        q==dssPreHashingType ? dssPreHashing_Interface :        \
        0)

#define xSM2SIG(crv,hash,q) (                                           \
        q==PKKeygenFunc ? (IntPtr)SM2SIG_Keygen :                       \
        q==PKSignFunc ? (IntPtr)SM2SIG_Sign :                           \
        q==PKVerifyFunc ? (IntPtr)SM2SIG_Verify :                       \
        q==PKIncSignInitFunc ? (IntPtr)SM2SIG_IncSign_Init :            \
        q==PKIncSignFinalFunc ? (IntPtr)SM2SIG_IncSign_Final :          \
        q==PKIncVerifyInitFunc ? (IntPtr)SM2SIG_IncVerify_Init :        \
        q==PKIncVerifyFinalFunc ? (IntPtr)SM2SIG_IncVerify_Final :      \
        q==PrivXctrlFunc ? (IntPtr)SM2SIG_Sign_Xctrl :                  \
        q==PubXctrlFunc ? (IntPtr)SM2SIG_Verify_Xctrl :                 \
        cSM2SIG(crv,hash,q) )

#define xSM2SIG_CtCodec(q) (                                    \
        q==PKSignFunc ? (IntPtr)SM2SIG_Sign :                   \
        q==PKVerifyFunc ? (IntPtr)SM2SIG_Verify :               \
        q==PKCtEncoder ? (IntPtr)SM2SIG_Encode_Signature :      \
        q==PKCtDecoder ? (IntPtr)SM2SIG_Decode_Signature :      \
        0)

IntPtr iSM2SIG_KeyCodec(int q);
IntPtr tSM2SIG(const CryptoParam_t *P, int q);
IntPtr iSM2SIG_CtCodec(int q);

#endif /* MySuiteA_ecdsa_h */
