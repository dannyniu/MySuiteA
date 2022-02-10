/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#ifndef MySuiteA_ecdsa_h
#define MySuiteA_ecdsa_h 1

#include "../2-hash/has-funcs-set.h"
#include "../2-ec/ecp-xyz.h"

typedef struct {
    // 4 32-bit words counted.
    uint32_t offset_d, offset_Q; // the entity keypair.
    uint32_t offset_k, offset_R; // ephemeral keypair.

    // 4 32-bit words counted.
    uint32_t offset_Tmp1, offset_Tmp2; // for ec_point_scale_accumulate.
    uint32_t offset_opctx;
    int32_t status;

    // 1 machine word counted.
    ecp_curve_t *curve;

    // The above members are common to both ECDH-KEM and ECDSA.
    // The key generation function assume such structure layout,
    // as it's intended that keygen function be shared between
    // ECDH-KEM and ECDSA.
    // ---
    
    // 5 machine words counted.
    size_t hlen;
    hash_funcs_set_t hfuncs;

    // 1 machine word counted.
    ptrdiff_t offset_hashctx;
} ECDSA_Priv_Ctx_Hdr_t;

// ${ [0].* } are that for domain parameters for the curve.
// ${ [1].* } are that for the hash function.
typedef CryptoParam_t ECDSA_Param_t[2];

void *ECDSA_Sign(
    ECSA_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

#endif /* MySuiteA_ecdsa_h */
