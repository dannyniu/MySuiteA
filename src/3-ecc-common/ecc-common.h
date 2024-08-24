/* DannyNiu/NJF, 2022-02-11. Public Domain. */

#ifndef MySuiteA_ecc_common_h
#define MySuiteA_ecc_common_h 1

#include "../2-ec/ecp-xyz.h"
#include "../2-hash/hash-funcs-set.h"
#include "../2-asn1/der-codec.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4 * 9 | 4 *10 | 8 * 6
typedef struct {
    // 4 32-bit words counted.
    uint32_t offset_d, offset_Q; // the entity keypair.
    uint32_t offset_k, offset_R; // ephemeral keypair.

    // 4 32-bit words counted.
    uint32_t offset_Tmp1, offset_Tmp2; // for ec_point_scale_accumulate.
    uint32_t offset_opctx;
    int32_t status; // refer to "2-rsa/pkcs1-padding.h".

    // 2 machine word counted.
    IntPtr context_type; // 1 for KEM, 2 for DSS.
    ecp_curve_t const *curve;

    // The above members are common to both ECDH-KEM and ECDSA.
    // The key generation function assume such structure layout,
    // as it's intended that keygen function be shared between
    // ECDH-KEM and ECDSA.
    // ---
} ECC_Base_Ctx_Hdr_t;

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4 *28 | 4 *32 | 8 *20
typedef struct {
    // 4 32-bit words counted.
    uint32_t offset_d, offset_Q; // the entity keypair.
    uint32_t offset_k, offset_R; // ephemeral keypair.

    // 4 32-bit words counted.
    uint32_t offset_Tmp1, offset_Tmp2; // for ec_point_scale_accumulate.
    uint32_t offset_opctx;
    int32_t status; // refer to "2-rsa/pkcs1-padding.h".

    // 2 machine word counted.
    IntPtr context_type; // 1 for KEM, 2 for DSS.
    ecp_curve_t const *curve;

    // The above members are common to both ECDH-KEM and ECDSA.
    // The key generation function assume such structure layout,
    // as it's intended that keygen function be shared between
    // ECDH-KEM and ECDSA.
    // ---

    // 2022-04-16:
    // As of now (date of the note), the only purpose of this field is
    // to hold the hash Z of SM2 DSS, which contain per-user info, which
    // is set through the Xctrl context-control function.
    uint8_t uinfo[64]; // Counted in align-spec as of 2022-04-16 14:50 p.m.

    // 2 machine words counted.
    size_t hlen;
    ptrdiff_t offset_hashctx;

    // 4 machine words counted.
    hash_funcs_set_t hfuncs;
} ECC_Hash_Ctx_Hdr_t;

#define ECC_SIZE_OF_CTX_HDR(hash)               \
    (hash(contextBytes) ?                       \
     sizeof(ECC_Hash_Ctx_Hdr_t) :               \
     sizeof(ECC_Base_Ctx_Hdr_t))

#define ECC_CTX_SIZE_X(crv,hash) (              \
        crv(bytesOpCtx) +                       \
        crv(bytesECXYZ) * 4 +                   \
        crv(bytesVLong) * 2 +                   \
        hash(contextBytes) +                    \
        ECC_SIZE_OF_CTX_HDR(hash) )

#define ECC_CTX_SIZE(...) ECC_CTX_SIZE_X(__VA_ARGS__)

#define ECC_CTX_INIT_X(type,crv,hash,...)               \
    ((type){                                            \
        .curve = (const void *)crv(ptrCurveDef),        \
        .status = 0,                                    \
        .offset_opctx = ECC_SIZE_OF_CTX_HDR(hash) +     \
        hash(contextBytes),                             \
        .offset_Q     = ECC_SIZE_OF_CTX_HDR(hash) +     \
        hash(contextBytes) +                            \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 0,                            \
        .offset_R     = ECC_SIZE_OF_CTX_HDR(hash) +     \
        hash(contextBytes) +                            \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 1,                            \
        .offset_Tmp1  = ECC_SIZE_OF_CTX_HDR(hash) +     \
        hash(contextBytes) +                            \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 2,                            \
        .offset_Tmp2  = ECC_SIZE_OF_CTX_HDR(hash) +     \
        hash(contextBytes) +                            \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 3,                            \
        .offset_d     = ECC_SIZE_OF_CTX_HDR(hash) +     \
        hash(contextBytes) +                            \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 4 +                           \
        crv(bytesVLong) * 0,                            \
        .offset_k     = ECC_SIZE_OF_CTX_HDR(hash) +     \
        hash(contextBytes) +                            \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 4 +                           \
        crv(bytesVLong) * 1,                            \
        __VA_ARGS__                                     \
    })

#define ECC_CTX_INIT(...) ECC_CTX_INIT_X(__VA_ARGS__)

#define ECC_BASE_CTX_T(...)                             \
    union {                                             \
        ECC_Base_Ctx_Hdr_t header;                      \
        uint8_t blob[ECC_CTX_SIZE(__VA_ARGS__)];        \
    }

#define ECC_HASH_CTX_T(...)                             \
    union {                                             \
        ECC_Hash_Ctx_Hdr_t header;                      \
        uint8_t blob[ECC_CTX_SIZE(__VA_ARGS__)];        \
    }

void topword_modmask(uint32_t *x, uint32_t const *m);

void ecc_canon_pubkey(
    ECC_Base_Ctx_Hdr_t *restrict x,
    ecp_xyz_t *restrict Q);

IntPtr ber_tlv_ecc_encode_dss_signature(BER_TLV_ENCODING_FUNC_PARAMS);
int    ber_tlv_ecc_decode_dss_signature(BER_TLV_DECODING_FUNC_PARAMS);

IntPtr ECC_Keygen(
    ECC_Base_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

IntPtr ECC_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr ECC_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr ECC_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr ECC_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

#endif /* MySuiteA_ecc_common_h */
