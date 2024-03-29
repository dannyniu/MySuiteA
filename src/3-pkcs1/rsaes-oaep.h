/* DannyNiu/NJF, 2021-09-10. Public Domain. */

#ifndef MySuiteA_RSAES_OAEP_h
#define MySuiteA_RSAES_OAEP_h 1

#include "pkcs1.h"

// returns x on success and NULL on failure.
void *RSAES_OAEP_Decode_Ciphertext(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t ctlen);

// returns x on success and NULL on failure.
// if ss is NULL, *sslen is set to its length.
void *RSAES_OAEP_Dec(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen);

void *RSAES_OAEP_Dec_Xctrl(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

// returns ct on success and NULL on failure.
// if ct is NULL, *ctlen is set to its length.
void *RSAES_OAEP_Encode_Ciphertext(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t *ctlen);

// returns ss on success and NULL on failure.
// by convention, if ss is NULL, *sslen is set to its length.
// however, because RSA accepts arbitrary-length message as input,
// the RSA-OAEP encrypt call will not change its value.
void *RSAES_OAEP_Enc(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng);

void *RSAES_OAEP_Enc_Xctrl(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

#define cRSAES_OAEP cRSA_PKCS1

#define xRSAES_OAEP(hmsg,hmgf,bits,primes,q) (                  \
        q==PKKeygenFunc ? (IntPtr)PKCS1_Keygen :                \
        q==PKEncFunc ? (IntPtr)RSAES_OAEP_Enc :                 \
        q==PKDecFunc ? (IntPtr)RSAES_OAEP_Dec :                 \
        q==PubXctrlFunc ? (IntPtr)RSAES_OAEP_Enc_Xctrl :        \
        q==PrivXctrlFunc ? (IntPtr)RSAES_OAEP_Dec_Xctrl :       \
        cRSAES_OAEP(hmsg,hmgf,bits,primes,q) )

#define xRSAES_OAEP_CtCodec(q) (                                \
        q==PKEncFunc ? (IntPtr)RSAES_OAEP_Enc :                 \
        q==PKDecFunc ? (IntPtr)RSAES_OAEP_Dec :                 \
        q==PKCtEncoder ? (IntPtr)RSAES_OAEP_Encode_Ciphertext : \
        q==PKCtDecoder ? (IntPtr)RSAES_OAEP_Decode_Ciphertext : \
        0)

IntPtr tRSAES_OAEP(const CryptoParam_t *P, int q);
IntPtr iRSAES_OAEP_CtCodec(int q);

enum {
    RSAES_OAEP_cmd_null     = 0,
    RSAES_OAEP_label_set    = 1,
    RSAES_OAEP_label_test   = 2,
};

#endif /* MySuiteA_RSAES_OAEP_h */
