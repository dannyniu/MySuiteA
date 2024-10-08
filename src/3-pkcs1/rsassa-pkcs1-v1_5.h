/* DannyNiu/NJF, 2022-05-07. Public Domain. */

#ifndef MySuiteA_RSASSA_PKCS1_v1_5_h
#define MySuiteA_RSASSA_PKCS1_v1_5_h 1

#include "pkcs1.h"

typedef struct {
    InitFunc_t  HashInitFunc;
    void const  *DER_Prefix;
    size_t      DER_Prefix_Len;
    size_t      Digest_Len;
} RSAEnc_HashOID;

extern const RSAEnc_HashOID HashOIDs_Table[];

// returns sig on success and NULL on failure.
// if sig is NULL, *siglen is set to its length.
void *RSAEncryptionWithHash_Encode_Signature(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen);

// returns x on success and NULL on failure.
void *RSAEncryptionWithHash_Sign(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

void *RSAEncryptionWithHash_IncSign_Init(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback);

void *RSAEncryptionWithHash_IncSign_Final(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen,
    void *restrict prng);

// returns x on success and NULL on failure.
void *RSAEncryptionWithHash_Decode_Signature(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t siglen);

// returns msg on success and NULL on failure.
void const *RSAEncryptionWithHash_Verify(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen);

void *RSAEncryptionWithHash_IncVerify_Init(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback);

void *RSAEncryptionWithHash_IncVerify_Final(
    PKCS1_Pub_Ctx_Hdr_t *restrict x);

#define cRSAEncryptionWithHash cRSA_PKCS1

#define xRSAEncryptionWithHash(hmsg,hmgf,bits,primes,q) (               \
        q==PKKeygenFunc ? (IntPtr)PKCS1_Keygen :                        \
        q==PKSignFunc ? (IntPtr)RSAEncryptionWithHash_Sign :            \
        q==PKVerifyFunc ? (IntPtr)RSAEncryptionWithHash_Verify :        \
        q==PKIncSignInitFunc ? (IntPtr)RSAEncryptionWithHash_IncSign_Init : \
        q==PKIncSignFinalFunc ? (IntPtr)RSAEncryptionWithHash_IncSign_Final : \
        q==PKIncVerifyInitFunc ? (IntPtr)RSAEncryptionWithHash_IncVerify_Init : \
        q==PKIncVerifyFinalFunc ? (IntPtr)RSAEncryptionWithHash_IncVerify_Final : \
        q==dssNonceNeeded ? false :                                     \
        q==dssExternRngNeededForNonce ? false :                         \
        q==dssPreHashingType ? dssPreHashing_Interface :                \
        cRSAEncryptionWithHash(hmsg,hmgf,bits,primes,q) )

#define xRSAEncryptionWithHash_CtCodec(q) (                             \
        q==PKSignFunc ? (IntPtr)RSAEncryptionWithHash_Sign :            \
        q==PKVerifyFunc ? (IntPtr)RSAEncryptionWithHash_Verify :        \
        q==PKCtEncoder ? (IntPtr)RSAEncryptionWithHash_Encode_Signature : \
        q==PKCtDecoder ? (IntPtr)RSAEncryptionWithHash_Decode_Signature : \
        0)

IntPtr tRSAEncryptionWithHash(const CryptoParam_t *P, int q);
IntPtr iRSAEncryptionWithHash_CtCodec(int q);

#endif /* MySuiteA_RSASSA_PKCS1_v1_5_h */
