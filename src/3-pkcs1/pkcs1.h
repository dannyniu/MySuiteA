/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#ifndef MySuiteA_pkcs1_h
#define MySuiteA_pkcs1_h 1

#include "../2-rsa/rsa.h"
#include "../2-rsa/pkcs1-padding.h"
#include "../2-asn1/der-codec.h"

typedef struct {
    ptrdiff_t offset_rsa_privctx;
    pkcs1_padding_oracles_base_t po_base;
} PKCS1_Priv_Ctx_Hdr_t;

// 2021-10-29:
//
// For asymmetric-key algorithms, parameters common for
// both private and public key operations come before
// parameters that may differ.
//
// For example, the crypto-objects for the hash functions
// used in RSA are placed at the head because they're used
// in both public key and private key operations.
//

// ${ [0...2].* } are that for the padding scheme.
// ${ [3...4].* } are that for the rsa algorithm.
typedef CryptoParam_t PKCS1_Priv_Param_t[5];

#define PKCS1_PRIV_CTX_PAYLOAD_SIZE_X(hmsg,hmgf,slen,bits,primes) (     \
        PKCS1_HASH_CTX_SIZE(hmsg,hmgf) +                                \
        RSA_PRIV_CTX_SIZE(bits,primes) )

#define PKCS1_PRIV_CTX_PAYLOAD_SIZE(...)        \
    PKCS1_PRIV_CTX_PAYLOAD_SIZE_X(__VA_ARGS__)

#define PKCS1_PRIV_CTX_SIZE_X(hmsg,hmgf,slen,bits,primes) (     \
        PKCS1_PRIV_CTX_PAYLOAD_SIZE(                            \
            hmsg,hmgf,slen,                                     \
            bits,primes) +                                      \
        sizeof(PKCS1_Priv_Ctx_Hdr_t) )

#define PKCS1_PRIV_CTX_SIZE(...)                \
    PKCS1_PRIV_CTX_SIZE_X(__VA_ARGS__)

#define PKCS1_PRIV_CTX_INIT_X(hmsg,hmgf,slen,bits,primes)       \
    ((PKCS1_Priv_Ctx_Hdr_t){                                    \
        .offset_rsa_privctx =                                   \
        sizeof(PKCS1_Priv_Ctx_Hdr_t) +                          \
        PKCS1_HASH_CTX_SIZE(hmsg,hmgf),                         \
        .po_base =                                              \
        PKCS1_PADDING_ORACLES_BASE_INIT(hmsg,hmgf,slen),        \
    })

#define PKCS1_PRIV_CTX_INIT(...)                \
    PKCS1_PRIV_CTX_INIT_X(__VA_ARGS__)

#define PKCS1_PRIV_CTX_T(...)                                           \
    struct {                                                            \
        PKCS1_Priv_Ctx_Hdr_t header;                                    \
        uint8_t payload[PKCS1_PRIV_CTX_PAYLOAD_SIZE(__VA_ARGS__)];      \
    }

typedef struct {
    ptrdiff_t offset_rsa_pubctx;
    pkcs1_padding_oracles_base_t po_base;
} PKCS1_Pub_Ctx_Hdr_t;

// ${ [0...2].* } are that for the padding scheme.
// ${ [3].* } is that for the rsa algorithm,
typedef CryptoParam_t PKCS1_Pub_Param_t[4];

#define PKCS1_PUB_CTX_PAYLOAD_SIZE_X(hmsg,hmgf,slen,bits) ( \
        PKCS1_HASH_CTX_SIZE(hmsg,hmgf) +            \
        RSA_PUB_CTX_SIZE(bits) )

#define PKCS1_PUB_CTX_PAYLOAD_SIZE(...)         \
    PKCS1_PUB_CTX_PAYLOAD_SIZE_X(__VA_ARGS__)

#define PKCS1_PUB_CTX_SIZE_X(hmsg,hmgf,slen,bits) ( \
        PKCS1_PUB_CTX_PAYLOAD_SIZE(                 \
            hmsg,hmgf,slen,bits) +                  \
        sizeof(PKCS1_Pub_Ctx_Hdr_t) )

#define PKCS1_PUB_CTX_SIZE(...) PKCS1_PUB_CTX_SIZE_X(__VA_ARGS__)

#define PKCS1_PUB_CTX_INIT(hmsg,hmgf,slen,bits)                 \
    ((PKCS1_Pub_Ctx_Hdr_t){                                     \
        .offset_rsa_pubctx =                                    \
        sizeof(ptrdiff_t) +                                     \
        PKCS1_PADDING_ORACLES_CTX_SIZE(hmsg,hmgf,slen),         \
        .po_base =                                              \
        PKCS1_PADDING_ORACLES_BASE_INIT(hmsg,hmgf,slen),        \
    })

#define PKCS1_PUB_CTX_T(...)                                            \
    struct {                                                            \
        PKCS1_Pub_Ctx_Hdr_t header;                                     \
        uint8_t payload[PKCS1_PUB_CTX_PAYLOAD_SIZE(__VA_ARGS__)];       \
    }

typedef struct {
    PKCS1_Padding_Oracles_Param_t aux_po;
    uint32_t aux_misc;
} PKCS1_Codec_Aux_t;

// Same notes as rsa_keygen in "rsa.h",
// as this function is a wrapper of it.
IntPtr PKCS1_Keygen(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
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
