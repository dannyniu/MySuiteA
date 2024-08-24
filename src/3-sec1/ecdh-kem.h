/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#ifndef MySuiteA_ecdh_kem_h
#define MySuiteA_ecdh_kem_h 1

#include "../3-ecc-common/ecc-common.h"

// In a typical Diffie-Hellman-like key exchange, each peer operates
// identically, i.e. that being peer-symmetric. However, some post-quantum
// PKE/KEM schemes the operation is peer-asymmetric.
//
// For code-based PKEs, it's because the encrypting peer is applying
// different operation than the decrypting peer; for lattice-based KEMs,
// the Fujisaki-Okamoto transformation dictates that the decrypting peer
// must do different additional work to verify that the ciphertext is
// not one that would tricks the decrypting oracle with methods like
// decryption failure amplification to guess private key bits.
//
// Additionally, it is intended that MySuiteA provide a uniform interface
// across all algorithms of same type - KEM is a more general form than
// key-agreement (and PKE) in terms of API design. And RSA encryption cannot
// fit in the form of key-agreement.
//
// All in all, ECDH is implemented as a KEM. And, the documents in the
// suite describe ECDH as ECDH-KEM to emphasize that it's not implemented
// in the form of a traditional key-agreement API.

// ${ [0].* } are that for curve domain parameters.
typedef CryptoParam_t ECDH_KEM_Param_t[1];

typedef ECC_Base_Ctx_Hdr_t ECDH_KEM_Ctx_Hdr_t;

IntPtr ECDH_KEM_Keygen(
    ECDH_KEM_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

IntPtr ECDH_KEM_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr ECDH_KEM_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr ECDH_KEM_Export_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr ECDH_KEM_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr ECDH_KEM_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

void *ECDH_KEM_Enc(
    ECDH_KEM_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng);

void *ECDH_KEM_Dec(
    ECDH_KEM_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen);

void *ECDH_KEM_Encode_Ciphertext(
    ECDH_KEM_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t *ctlen);

void *ECDH_KEM_Decode_Ciphertext(
    ECDH_KEM_Ctx_Hdr_t *restrict x,
    void const *restrict ct, size_t ctlen);

int ECDH_KEM_PKParams(int index, CryptoParam_t *out);

#define xECDH_KEM_KeyCodec(q) (                                         \
        q==PKKeygenFunc ? (IntPtr)ECDH_KEM_Keygen :                     \
        q==PKPrivkeyEncoder ? (IntPtr)ECDH_KEM_Encode_PrivateKey :      \
        q==PKPrivkeyDecoder ? (IntPtr)ECDH_KEM_Decode_PrivateKey :      \
        q==PKPubkeyExporter ? (IntPtr)ECDH_KEM_Export_PublicKey :       \
        q==PKPubkeyEncoder ? (IntPtr)ECDH_KEM_Encode_PublicKey :        \
        q==PKPubkeyDecoder ? (IntPtr)ECDH_KEM_Decode_PublicKey :        \
        0)

#define cECDH_KEM(crv,q) (                                      \
        q==bytesCtxPriv ? ECC_CTX_SIZE(crv,CRYPTO_OBJ_NULL) :   \
        q==bytesCtxPub ? ECC_CTX_SIZE(crv,CRYPTO_OBJ_NULL) :    \
        q==isParamDetermByKey ? false :                         \
        0)

#define xECDH_KEM(crv,q) (                              \
        q==PKKeygenFunc ? (IntPtr)ECDH_KEM_Keygen :     \
        q==PKEncFunc ? (IntPtr)ECDH_KEM_Enc :           \
        q==PKDecFunc ? (IntPtr)ECDH_KEM_Dec :           \
        cECDH_KEM(crv,q) )

#define xECDH_KEM_CtCodec(q) (                                  \
        q==PKEncFunc ? (IntPtr)ECDH_KEM_Enc :                   \
        q==PKDecFunc ? (IntPtr)ECDH_KEM_Dec :                   \
        q==PKCtEncoder ? (IntPtr)ECDH_KEM_Encode_Ciphertext :   \
        q==PKCtDecoder ? (IntPtr)ECDH_KEM_Decode_Ciphertext :   \
        0)

IntPtr iECDH_KEM_KeyCodec(int q);
IntPtr tECDH_KEM(const CryptoParam_t *P, int q);
IntPtr iECDH_KEM_CtCodec(int q);

#endif /* MySuiteA_ecdh_kem_h */
