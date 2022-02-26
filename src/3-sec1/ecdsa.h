/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#ifndef MySuiteA_ecdsa_h
#define MySuiteA_ecdsa_h 1

#include "sec1-common.h"
#include "../2-hash/hash-funcs-set.h"

// ${ [0].* } are that for curve domain parameters.
// ${ [1].* } are that for the hash function.
typedef CryptoParam_t ECDSA_Param_t[2];

typedef SEC1_Hash_Ctx_Hdr_t ECDSA_Ctx_Hdr_t;

#define ECDSA_CTX_INIT_X(crv,hash) SEC1_CTX_INIT_X(     \
        ECDSA_Ctx_Hdr_t,                                \
        crv, hash,                                      \
        .hlen = hash(outBytes),                         \
        .hfuncs = HASH_FUNCS_SET_INIT(hash),            \
        .context_type = 2,                              \
        .offset_hashctx = sizeof(ECDSA_Ctx_Hdr_t))

#define ECDSA_CTX_INIT(...) ECDSA_CTX_INIT_X(__VA_ARGS__)

IntPtr ECDSA_Keygen(
    ECDSA_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

IntPtr ECDSA_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr ECDSA_Decode_PrivateKey(
    void *any, void const *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr ECDSA_Export_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr ECDSA_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr ECDSA_Decode_PublicKey(
    void *any, void const *enc, size_t enclen, CryptoParam_t *restrict param);

#define xECDSA_KeyCodec(q) (                                    \
        q==PKKeygenFunc ? (IntPtr)ECDSA_Keygen :                \
        q==PKPrivkeyEncoder ? (IntPtr)ECDSA_Encode_PrivateKey : \
        q==PKPrivkeyDecoder ? (IntPtr)ECDSA_Decode_PrivateKey : \
        q==PKPubkeyExporter ? (IntPtr)ECDSA_Export_PublicKey :  \
        q==PKPubkeyEncoder ? (IntPtr)ECDSA_Encode_PublicKey :   \
        q==PKPubkeyDecoder ? (IntPtr)ECDSA_Decode_PublicKey :   \
        0)

IntPtr iECDSA_KeyCodec(int q);

void *ECDSA_Sign(
    ECDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

void const *ECDSA_Verify(
    ECDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen);

void *ECDSA_Encode_Signature(
    ECDSA_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen);

void *ECDSA_Decode_Signature(
    ECDSA_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t siglen);

#define cECDSA(crv,hash,q) (                            \
        q==bytesCtxPriv ? SEC1_CTX_SIZE(crv,hash) :     \
        q==bytesCtxPub ? SEC1_CTX_SIZE(crv,hash) :      \
        q==isParamDetermByKey ? 0 :                     \
        0)

#define xECDSA(crv,hash,q) (                            \
        q==PKParamsFunc ? (IntPtr)ECDSA_PKParams :      \
        q==PKKeygenFunc ? (IntPtr)ECDSA_Keygen :        \
        q==PKSignFunc ? (IntPtr)ECDSA_Sign :            \
        q==PKVerifyFunc ? (IntPtr)ECDSA_Verify :        \
        cECDSA(crv,hash,q) )

#define xECDSA_CtCodec(q) (                                     \
        q==PKSignFunc ? (IntPtr)ECDSA_Sign :                    \
        q==PKVerifyFunc ? (IntPtr)ECDSA_Verify :                \
        q==PKCtEncoder ? (IntPtr)ECDSA_Encode_Signature :       \
        q==PKCtDecoder ? (IntPtr)ECDSA_Decode_Signature :       \
        0)

IntPtr tECDSA(const CryptoParam_t *P, int q);
IntPtr iECDSA_CtCodec(int q);

#endif /* MySuiteA_ecdsa_h */
