/* DannyNiu/NJF, 2021-09-10. Public Domain. */

#ifndef MySuiteA_RSASSA_PSS_h
#define MySuiteA_RSASSA_PSS_h 1

#include "pkcs1.h"

// returns sig on success and NULL on failure.
// if sig is NULL, *siglen is set to its length.
void *RSASSA_PSS_Encode_Signature(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen);

// returns x on success and NULL on failure.
void *RSASSA_PSS_Sign(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

void *RSASSA_PSS_Sign(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

void *RSASSA_PSS_IncSign_Init(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback);

void *RSASSA_PSS_IncSign_Final(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen,
    void *restrict prng);

void *RSASSA_PSS_Sign_Xctrl(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

// returns x on success and NULL on failure.
void *RSASSA_PSS_Decode_Signature(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t siglen);

// returns msg on success and NULL on failure.
void const *RSASSA_PSS_Verify(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen);

void *RSASSA_PSS_IncVerify_Init(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback);

void *RSASSA_PSS_IncVerify_Final(
    PKCS1_Pub_Ctx_Hdr_t *restrict x);

void *RSASSA_PSS_Verify_Xctrl(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

#define cRSASSA_PSS cRSA_PKCS1

#define xRSASSA_PSS(hmsg,hmgf,bits,primes,q) (                          \
        q==PKKeygenFunc ? (IntPtr)PKCS1_Keygen :                        \
        q==PKSignFunc ? (IntPtr)RSASSA_PSS_Sign :                       \
        q==PKVerifyFunc ? (IntPtr)RSASSA_PSS_Verify :                   \
        q==PKIncSignInitFunc ? (IntPtr)RSASSA_PSS_IncSign_Init :        \
        q==PKIncSignFinalFunc ? (IntPtr)RSASSA_PSS_IncSign_Final :      \
        q==PKIncVerifyInitFunc ? (IntPtr)RSASSA_PSS_IncVerify_Init :    \
        q==PKIncVerifyFinalFunc ? (IntPtr)RSASSA_PSS_IncVerify_Final :  \
        q==PrivXctrlFunc ? (IntPtr)RSASSA_PSS_Sign_Xctrl :              \
        q==PubXctrlFunc ? (IntPtr)RSASSA_PSS_Verify_Xctrl :             \
        q==dssNonceNeeded ? true :                                      \
        q==dssExternRngNeededForNonce ? true :                          \
        q==dssPreHashingType ? dssPreHashing_Interface :                \
        cRSASSA_PSS(hmsg,hmgf,bits,primes,q) )

#define xRSASSA_PSS_CtCodec(q) (                                \
        q==PKSignFunc ? (IntPtr)RSASSA_PSS_Sign :               \
        q==PKVerifyFunc ? (IntPtr)RSASSA_PSS_Verify :           \
        q==PKCtEncoder ? (IntPtr)RSASSA_PSS_Encode_Signature :  \
        q==PKCtDecoder ? (IntPtr)RSASSA_PSS_Decode_Signature :  \
        0)

IntPtr tRSASSA_PSS(const CryptoParam_t *P, int q);
IntPtr iRSASSA_PSS_CtCodec(int q);

enum {
    RSASSA_PSS_cmd_null     = 0,

    // For the following 2 commands, No check is done,
    // and any occurrence of error will be delayed until
    // actual signing/verifying.

    // The salt length is specified through the ``flags'' parameter.
    RSASSA_PSS_set_slen     = 1,

    // The salt length is returned after casting to pointer, which can be
    // casted back to integer.
    RSASSA_PSS_get_slen     = 2,
};

#endif /* MySuiteA_RSASSA_PSS_h */
