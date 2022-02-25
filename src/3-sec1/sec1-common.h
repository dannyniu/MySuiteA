/* DannyNiu/NJF, 2022-02-11. Public Domain. */

#ifndef MySuiteA_sec1_common_h
#define MySuiteA_sec1_common_h 1

#include "../2-ec/ecp-xyz.h"
#include "../2-hash/hash-funcs-set.h"

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
} SEC1_Base_Ctx_Hdr_t;

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4 *12 | 4 *16 | 8 *12
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
    
    // 2 machine words counted.
    size_t hlen;
    ptrdiff_t offset_hashctx;
    
    // 4 machine words counted.
    hash_funcs_set_t hfuncs;
} SEC1_Hash_Ctx_Hdr_t;

#define SEC1_SIZE_OF_CTX_HDR(hash)              \
    (hash ?                                     \
     sizeof(SEC1_Hash_Ctx_Hdr_t) :              \
     sizeof(SEC1_Base_Ctx_Hdr_t))

#define SEC1_CTX_SIZE_X(crv,hash) (             \
        crv(bytesOpCtx) +                       \
        crv(bytesECXYZ) * 4 +                   \
        crv(bytesVLong) * 2 +                   \
        (hash ? hash(contextBytes) : 0) +       \
        SEC1_SIZE_OF_CTX_HDR(hash) )

#define SEC1_CTX_SIZE(...) SEC1_CTX_SIZE_X(__VA_ARGS__)

#define SEC1_CTX_INIT_X(type,crv,hash,...)              \
    ((type){                                            \
        .curve = (const void *)crv(ptrCurveDef),        \
        .status = 0,                                    \
        .offset_opctx = SEC1_SIZE_OF_CTX_HDR(hash) +    \
        (hash ? hash(contextBytes) : 0),                \
        .offset_Q    = SEC1_SIZE_OF_CTX_HDR(hash) +     \
        (hash ? hash(contextBytes) : 0) +               \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 0,                            \
        .offset_R    = SEC1_SIZE_OF_CTX_HDR(hash) +     \
        (hash ? hash(contextBytes) : 0) +               \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 1,                            \
        .offset_Tmp1 = SEC1_SIZE_OF_CTX_HDR(hash) +     \
        (hash ? hash(contextBytes) : 0) +               \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 2,                            \
        .offset_Tmp2 = SEC1_SIZE_OF_CTX_HDR(hash) +     \
        (hash ? hash(contextBytes) : 0) +               \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 3,                            \
        .offset_d    = SEC1_SIZE_OF_CTX_HDR(hash) +     \
        (hash ? hash(contextBytes) : 0) +               \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 4 +                           \
        crv(bytesVLong) * 0,                            \
        .offset_k    = SEC1_SIZE_OF_CTX_HDR(hash) +     \
        (hash ? hash(contextBytes) : 0) +               \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 4 +                           \
        crv(bytesVLong) * 1,                            \
        __VA_ARGS__                                     \
    })

#define SEC1_CTX_INIT(...) SEC1_CTX_INIT_X(__VA_ARGS__)

void topword_modmask(uint32_t *x, uint32_t const *m);
IntPtr SEC1_Keygen(
    SEC1_Base_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

IntPtr SEC1_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr SEC1_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr SEC1_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr SEC1_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

#endif /* MySuiteA_sec1_common_h */
