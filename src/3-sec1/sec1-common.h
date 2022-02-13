/* DannyNiu/NJF, 2022-02-11. Public Domain. */

#ifndef MySuiteA_sec1_common_h
#define MySuiteA_sec1_common_h 1

#include "../2-ec/ecp-xyz.h"

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
} SEC1_Common_Priv_Ctx_Hdr_t;

void SEC1_Keygen(
    SEC1_Common_Priv_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen, void *restrict prng);

#endif /* MySuiteA_sec1_common_h */
