/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#ifndef MySuiteA_ecdsa_h
#define MySuiteA_ecdsa_h 1

#include "sec1-common.h"
#include "../2-hash/hash-funcs-set.h"

// ${ [0].* } are that for curve domain parameters.
// ${ [1].* } are that for the hash function.
typedef CryptoParam_t ECDSA_Param_t[2];

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
} ECDSA_Ctx_Hdr_t;

#define ECDSA_CTX_SIZE_X(crv,hash) (            \
        crv(bytesOpCtx) +                       \
        crv(bytesECXYZ) * 4 +                   \
        crv(bytesVLong) * 2 +                   \
        hash(contextBytes) +                    \
        sizeof(ECDSA_Ctx_Hdr_t) )

#define ECDSA_CTX_SIZE(...) ECDSA_CTX_SIZE_X(__VA_ARGS__)

#define ECDSA_CTX_INIT_X(crv,hash)                      \
    ((ECDSA_Ctx_Hdr_t){                                 \
        .hlen = hash(outBytes),                         \
        .hfuncs = HASH_FUNCS_SET_INIT(hash),            \
        .curve = (const void *)crv(ptrCurveDef),        \
        .offset_hashctx = sizeof(ECDSA_Ctx_Hdr_t),      \
        .status = 0,                                    \
        .context_type = 2,                              \
        .offset_opctx = sizeof(ECDSA_Ctx_Hdr_t) +       \
        hash(contextBytes),                             \
        .offset_Q    = sizeof(ECDSA_Ctx_Hdr_t) +        \
        hash(contextBytes) +                            \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 0,                            \
        .offset_R    = sizeof(ECDSA_Ctx_Hdr_t) +        \
        hash(contextBytes) +                            \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 1,                            \
        .offset_Tmp1 = sizeof(ECDSA_Ctx_Hdr_t) +        \
        hash(contextBytes) +                            \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 2,                            \
        .offset_Tmp2 = sizeof(ECDSA_Ctx_Hdr_t) +        \
        hash(contextBytes) +                            \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 3,                            \
        .offset_d    = sizeof(ECDSA_Ctx_Hdr_t) +        \
        hash(contextBytes) +                            \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 4 +                           \
        crv(bytesVLong) * 0,                            \
        .offset_k    = sizeof(ECDSA_Ctx_Hdr_t) +        \
        hash(contextBytes) +                            \
        crv(bytesOpCtx) +                               \
        crv(bytesECXYZ) * 4 +                           \
        crv(bytesVLong) * 1,                            \
    })

#define ECDSA_CTX_INIT(...) ECDSA_CTX_INIT_X(__VA_ARGS__)

IntPtr ECDSA_Keygen(
    ECDSA_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

void *ECDSA_Sign(
    ECDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

void const *ECDSA_Verify(
    ECDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen);

#endif /* MySuiteA_ecdsa_h */
