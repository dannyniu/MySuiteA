/* DannyNiu/NJF, 2021-08-31. Public Domain */

#ifndef MySuiteA_pkcs1_padding_h
#define MySuiteA_pkcs1_padding_h 1

#include "../2-hash/hash-funcs-set.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4 * 8 | 4 *12 | 8 *10
typedef struct {
    // For public-key encryption:
    // - 1: OK.
    // - -1: Some encryption error.
    // For private-key decryption:
    // - 0: ciphertext decoded and ready for decryption.
    // - >0: indicates the length of the decrypted plaintext.
    // - <0: decryption failure.
    //
    // For signature generation:
    // - 1. OK.
    // - 2. The input message had been hashed and the digest
    //      don't need to be recomputed. This only occurs during
    //      the hand-over from the hedged signing subroutine to
    //      the internal PRNG-based signing subroutine.
    // - 3. Same as 2, except the ``uinfo'' field is prepended to
    //      the message when hashing. This is used by DSS schemes
    //      supporting user info such as SM2-DSS.
    // - -1. Some signing error.
    // For signature verification:
    // - 0: signature decoded and ready for verification.
    // - 1: signature valid.
    // - -1: signature invalid.
    int32_t             status;

    // Length of the salt in RSASSA-PSS.
    uint32_t            slen;

    uint32_t            hlen_msg;
    uint32_t            hlen_mgf;
    hash_funcs_set_t    hfuncs_msg, hfuncs_mgf;
} pkcs1_padding_oracles_base_t;

#define PKCS1_PADDING_ORACLES_BASE_INIT(hmsg, hmgf, saltlen)    \
    ((pkcs1_padding_oracles_base_t){                            \
        .status = 0,                                            \
        .slen = saltlen,                                        \
        .hlen_msg = OUT_BYTES(hmsg),                            \
        .hlen_mgf = OUT_BYTES(hmgf),                            \
        .hfuncs_msg = HASH_FUNCS_SET_INIT(hmsg),                \
        .hfuncs_mgf = HASH_FUNCS_SET_INIT(hmgf),                \
    })

#define PKCS1_PADDING_ORACLES_T(...)            \
    struct {                                    \
        pkcs1_padding_oracles_base_t base;      \
        uint8_t hashctx[__VA_ARGS__];           \
    }

typedef PKCS1_PADDING_ORACLES_T() pkcs1_padding_oracles_t;

// ${ [0].info } is the crypto-object for the message hash function.
// ${ [1].info } is the crypto-object for the MGF hash function.
// ${ [2].aux } is the length of the salt ("sLen" in the doc).
typedef CryptoParam_t PKCS1_Padding_Oracles_Param_t[3];

#define PKCS1_HASH_CTX_SIZE_X(hmsg,hmgf)        \
    (CTX_BYTES(hmsg) > CTX_BYTES(hmgf) ?        \
     CTX_BYTES(hmsg) : CTX_BYTES(hmgf))

#define PKCS1_HASH_CTX_SIZE(hmsg,hmgf)          \
    PKCS1_HASH_CTX_SIZE_X(hmsg,hmgf)

// 2021-09-03: See 2021-09-03b note in "notes.md".
#define PKCS1_PADDING_ORACLES_CTX_SIZE_X(hmsg,hmgf,saltlen) (   \
        sizeof(pkcs1_padding_oracles_base_t) +                  \
        PKCS1_HASH_CTX_SIZE(hmsg,hmgf) )

#define PKCS1_PADDING_ORACLES_CTX_SIZE(...)             \
    PKCS1_PADDING_ORACLES_CTX_SIZE_X(__VA_ARGS__)

void mgf1_pkcs1(
    pkcs1_padding_oracles_t *restrict x,
    void const *restrict in, size_t inlen,
    void *restrict out, size_t outlen, int xor);

void mgf_xof(
    pkcs1_padding_oracles_t *restrict x,
    void const *restrict in, size_t inlen,
    void *restrict out, size_t outlen, int xor);

void mgf_auto(
    pkcs1_padding_oracles_t *restrict x,
    void const *restrict in, size_t inlen,
    void *restrict out, size_t outlen, int xor);

#endif /* MySuiteA_pkcs1_padding_h */
