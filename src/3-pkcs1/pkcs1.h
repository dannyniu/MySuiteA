/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#ifndef MySuiteA_pkcs1_h
#define MySuiteA_pkcs1_h 1

#include "../2-rsa/rsa.h"
#include "../2-rsa/pkcs1-padding.h"
#include "../2-asn1/der-codec.h"

typedef struct {
    ptrdiff_t offset_rsa_privctx;
    pkcs1_padding_oracles_base_t po_base;
} PKCS1_Private_Context_t;

typedef struct {
    PKCS1_Padding_Oracles_Param_t params_po;
    RSA_Private_Param_t params_rsa;
} PKCS1_Private_Param_t;

#define PKCS1_PRIVATE_CONTEXT_SIZE_X(bits,primes,hmsg,hmgf,slen) (      \
        sizeof(PKCS1_Private_Context_t) +                               \
        PKCS1_HASH_CTX_SIZE(hmsg,hmgf) +                                \
        RSA_PRIVATE_CONTEXT_SIZE(bits,primes) )

#define PKCS1_PRIVATE_CONTEXT_SIZE(...)       \
    PKCS1_PRIVATE_CONTEXT_SIZE_X(__VA_ARGS__)

#define PKCS1_PRIVATE_CONTEXT_INIT_X(bits,primes,hmsg,hmgf,slen)        \
    ((PKCS1_Private_Context_t){                                         \
        .offset_rsa_privctx =                                           \
        sizeof(PKCS1_Private_Context_t) +                               \
        PKCS1_HASH_CTX_SIZE(hmsg,hmgf),                                 \
        .po_base =                                                      \
        PKCS1_PADDING_ORACLES_BASE_INIT(hmsg,hmgf,slen),                \
    })

#define PKCS1_PRIVATE_CONTEXT_INIT(...)         \
    PKCS1_PRIVATE_CONTEXT_INIT_X(__VA_ARGS__)

// The following macros are run-time only.
#define PKCS1_PRIVATE_PARAM_ENTUPLE(bits,primes,hmsg,hmgf,slen)         \
    ((PKCS1_Private_Param_t){                                           \
        .params_po =                                                    \
        PKCS1_PADDING_ORACLES_PARAM_ENTUPLE(hmsg,hmgf,slen),            \
        .params_rsa =                                                   \
        RSA_PRIVATE_PARAM_ENTUPLE(bits,primes)                          \
    })

#define PKCS1_PRIVATE_PARAM_DETUPLE(obj)                        \
    RSA_PRIVATE_PARAM_DETUPLE((obj).params_rsa),                \
        PKCS1_PADDING_ORACLES_PARAM_DETUPLE((obj).params_po)

typedef struct {
    ptrdiff_t offset_rsa_pubctx;
    pkcs1_padding_oracles_base_t po_base;
} PKCS1_Public_Context_t;

#define PKCS1_PUBLIC_CONTEXT_SIZE_X(bits,hmsg,hmgf,slen) (      \
        sizeof(PKCS1_Public_Context_t) +                        \
        PKCS1_HASH_CTX_SIZE(hmsg,hmgf) +                        \
        RSA_PUBLIC_CONTEXT_SIZE(bits) )

#define PKCS1_PUBLIC_CONTEXT_SIZE(...)          \
    PKCS1_PUBLIC_CONTEXT_SIZE_X(__VA_ARGS__)

#define PKCS1_PUBLIC_CONTEXT_INIT(bits,hmsg,hmgf,slen)          \
    ((PKCS1_Public_Context_t){                                  \
        .offset_rsa_pubctx =                                    \
        sizeof(ptrdiff_t) +                                     \
        PKCS1_PADDING_ORACLES_CTX_SIZE(hmsg,hmgf,slen),         \
        .po_base =                                              \
        PKCS1_PADDING_ORACLES_BASE_INIT(hmsg,hmgf,slen),        \
    })

typedef struct {
    PKCS1_Padding_Oracles_Param_t aux_po;
    uint32_t aux_misc;
} PKCS1_Codec_Aux_t;

// Same notes as rsa_keygen in "rsa.h",
// as this function is a wrapper of it.
IntPtr PKCS1_Keygen(
    PKCS1_Private_Context_t *restrict x,
    PKCS1_Private_Param_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

// Codec functions prefixed with PKCS1 always work with
// ASN.1 DER coded keys.
//
// For decoding functions, aux points to an object of type
// PKCS1_Codec_Aux_t. Such object holds information necessary
// for estimating the memory usage for padding oracle data
// structure. As such, it's necessary to setup its aux_po member
// at minimum.
int32_t PKCS1_Encode_RSAPrivateKey(BER_TLV_ENCODING_FUNC_PARAMS);
int32_t PKCS1_Decode_RSAPrivateKey(BER_TLV_DECODING_FUNC_PARAMS);
int32_t PKCS1_Encode_RSAPublicKey(BER_TLV_ENCODING_FUNC_PARAMS);
int32_t PKCS1_Decode_RSAPublicKey(BER_TLV_DECODING_FUNC_PARAMS);

#endif /* MySuiteA_pkcs1_h */
