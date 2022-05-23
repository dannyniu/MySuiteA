/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#ifndef MySuiteA_pkcs1_h
#define MySuiteA_pkcs1_h 1

#include "../2-rsa/rsa.h"
#include "../2-rsa/pkcs1-padding.h"
#include "../2-asn1/der-codec.h"

IntPtr PKCS1_NullHash(int q);

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: Error | 4 *13 | 8 *11
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
typedef CryptoParam_t PKCS1_RSA_Param_t[5];

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

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: Error | 4 *13 | 8 *11
typedef struct {
    ptrdiff_t offset_rsa_pubctx;
    pkcs1_padding_oracles_base_t po_base;
} PKCS1_Pub_Ctx_Hdr_t;

// primes is ignored in public contexts' macros,
// as it's only applicable to private contexts.
#define PKCS1_PUB_CTX_PAYLOAD_SIZE_X(hmsg,hmgf,slen,bits,primes) (    \
        PKCS1_HASH_CTX_SIZE(hmsg,hmgf) +                              \
        RSA_PUB_CTX_SIZE(bits) )

#define PKCS1_PUB_CTX_PAYLOAD_SIZE(...)         \
    PKCS1_PUB_CTX_PAYLOAD_SIZE_X(__VA_ARGS__)

#define PKCS1_PUB_CTX_SIZE_X(hmsg,hmgf,slen,bits,primes) (      \
        PKCS1_PUB_CTX_PAYLOAD_SIZE(                             \
            hmsg,hmgf,slen,bits,primes) +                       \
        sizeof(PKCS1_Pub_Ctx_Hdr_t) )

#define PKCS1_PUB_CTX_SIZE(...) PKCS1_PUB_CTX_SIZE_X(__VA_ARGS__)

#define PKCS1_PUB_CTX_INIT(hmsg,hmgf,slen,bits,primes)          \
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

IntPtr PKCS1_Keygen(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

// Codec functions prefixed with PKCS1 always work with
// ASN.1 DER coded keys.
//
// For decoding functions, ``param'' points to an array of ``CryptoParam_t''
// objects. This array is initialized with the padding parameters (hash
// functions and salt length). These information contributes to the estimate
// of the required space of the working context.
//
// In short, ``aux'' contains the same thing as ``param'' in ``PKCS1_Keygen''.
IntPtr PKCS1_Encode_RSAPrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr PKCS1_Decode_RSAPrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr PKCS1_Export_RSAPublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr PKCS1_Encode_RSAPublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr PKCS1_Decode_RSAPublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

int PKCS1_PKParams(int index, CryptoParam_t *out);

#define xPKCS1_KeyCodec(q) (                                            \
        q==PKKeygenFunc ? (IntPtr)PKCS1_Keygen :                        \
        q==PKPrivkeyEncoder ? (IntPtr)PKCS1_Encode_RSAPrivateKey :      \
        q==PKPrivkeyDecoder ? (IntPtr)PKCS1_Decode_RSAPrivateKey :      \
        q==PKPubkeyExporter ? (IntPtr)PKCS1_Export_RSAPublicKey :       \
        q==PKPubkeyEncoder ? (IntPtr)PKCS1_Encode_RSAPublicKey :        \
        q==PKPubkeyDecoder ? (IntPtr)PKCS1_Decode_RSAPublicKey :        \
        0)

IntPtr iPKCS1_KeyCodec(int q);

#define cRSA_PKCS1(hmsg,hmgf,slen,bits,primes,q) (      \
        q==bytesCtxPriv ? PKCS1_PRIV_CTX_SIZE(          \
            hmsg,hmgf,slen,bits,primes) :               \
        q==bytesCtxPub ? PKCS1_PUB_CTX_SIZE(            \
            hmsg,hmgf,slen,bits,primes) :               \
        q==isParamDetermByKey ? true :                  \
        0)

#endif /* MySuiteA_pkcs1_h */
