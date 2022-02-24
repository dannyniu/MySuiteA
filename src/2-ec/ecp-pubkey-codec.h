/* DannyNiu/NJF, 2022-02-23. Public Domain. */

#ifndef MySuiteA_ecc_ecp_pubkey_codec_h
#define MySuiteA_ecc_ecp_pubkey_codec_h 1

#include "ecp-xyz.h"

ecp_xyz_t *ecp_point_decode(
    ecp_xyz_t *restrict Q,
    void const *restrict enc,
    size_t enclen,
    ecp_xyz_t *restrict tinf,
    ecp_xyz_t *restrict tmp1,
    ecp_xyz_t *restrict tmp2,
    ecp_opctx_t *restrict opctx,
    ecp_curve_t const *restrict curve);

void *ecp_point_encode(
    ecp_xyz_t const *restrict Q,
    void *restrict enc, size_t enclen,
    ecp_curve_t const *restrict curve);

#endif /* MySuiteA_ecc_ecp_pubkey_codec_h */
