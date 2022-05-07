/* DannyNiu/NJF, 2022-05-07. Public Domain. */

#ifndef MySuiteA_RSAEncryption_h
#define MySuiteA_RSAEncryption_h 1

#include "pkcs1.h"

// returns x on success and NULL on failure.
void *RSAEncryption_Decode_Ciphertext(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t ctlen);

// returns x on success and NULL on failure.
// if ss is NULL, *sslen is set to its length.
void *RSAEncryption_Dec(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen);

// returns ct on success and NULL on failure.
// if ct is NULL, *ctlen is set to its length.
void *RSAEncryption_Encode_Ciphertext(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t *ctlen);

// returns ss on success and NULL on failure.
// by convention, if ss is NULL, *sslen is set to its length.
// however, because RSA accepts arbitrary-length message as input,
// the RSA-OAEP encrypt call will not change its value.
void *RSAEncryption_Enc(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng);

#define cRSAEncryption cRSA_PKCS1

#define xRSAEncryption(hmsg,hmgf,slen,bits,primes,q) (             \
        q==PKParamsFunc ? (IntPtr)PKCS1_PKParams :              \
        q==PKKeygenFunc ? (IntPtr)PKCS1_Keygen :                \
        q==PKEncFunc ? (IntPtr)RSAEncryption_Enc :                 \
        q==PKDecFunc ? (IntPtr)RSAEncryption_Dec :                 \
        cRSAEncryption(hmsg,hmgf,slen,bits,primes,q) )

#define xRSAEncryption_CtCodec(q) (                                \
        q==PKEncFunc ? (IntPtr)RSAEncryption_Enc :                 \
        q==PKDecFunc ? (IntPtr)RSAEncryption_Dec :                 \
        q==PKCtEncoder ? (IntPtr)RSAEncryption_Encode_Ciphertext : \
        q==PKCtDecoder ? (IntPtr)RSAEncryption_Decode_Ciphertext : \
        0)

IntPtr tRSAEncryption(const CryptoParam_t *P, int q);
IntPtr iRSAEncryption_CtCodec(int q);

#endif /* MySuiteA_RSAEncryption_h */
