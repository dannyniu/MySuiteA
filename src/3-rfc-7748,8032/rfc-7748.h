/* DannyNiu/NJF, 2022-04-27. Public Domain. */

#ifndef MySuiteA_rfc_7748_h
#define MySuiteA_rfc_7748_h 1

#include "../2-ec/ecMt.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4 * 5 | 4 * 6 | 8 * 4
typedef struct {
    uint32_t offset_k, offset_K; // private and public key.
    uint32_t offset_P; // public key from the peer.
    uint32_t offset_opctx;
    IntPtr status;
    ecp_imod_aux_t const *imod_aux;
} XECDH_Ctx_Hdr_t;

#define XECDH_CTX_SIZE(bits) (                  \
        sizeof(XECDH_Ctx_Hdr_t) +               \
        ECMT_OPCTX_SIZE(bits) +                 \
        VLONG_BITS_SIZE(bits) * 3               \
        )

#define XECDH_CTX_HDR_INIT(bits)                        \
    ((XECDH_Ctx_Hdr_t){                                 \
        .offset_opctx = sizeof(XECDH_Ctx_Hdr_t),        \
        .offset_k = sizeof(XECDH_Ctx_Hdr_t) +           \
        ECMT_OPCTX_SIZE(bits) +                         \
        VLONG_BITS_SIZE(bits) * 0,                      \
        .offset_K = sizeof(XECDH_Ctx_Hdr_t) +           \
        ECMT_OPCTX_SIZE(bits) +                         \
        VLONG_BITS_SIZE(bits) * 1,                      \
        .offset_P = sizeof(XECDH_Ctx_Hdr_t) +           \
        ECMT_OPCTX_SIZE(bits) +                         \
        VLONG_BITS_SIZE(bits) * 2,                      \
        .status = 0,                                    \
    })

#endif /* MySuiteA_rfc_7748_h */
