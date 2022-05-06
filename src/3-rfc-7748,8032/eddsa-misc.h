/* DannyNiu/NJF, 2022-05-05. Public Domain. */

#ifndef MySuiteA_eddsa_misc_h
#define MySuiteA_eddsa_misc_h 1

#include "eddsa.h"

void eddsa_ctxinit_basic(
    EdDSA_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param);

void eddsa_privkey_reload(EdDSA_Ctx_Hdr_t *x);

void eddsa_canon_pubkey(
    EdDSA_Ctx_Hdr_t *restrict x,
    ecEd_xytz_t *restrict Q);

void eddsa_point_enc(
    EdDSA_Ctx_Hdr_t const *restrict x,
    uint8_t buf[restrict],
    ecEd_xytz_t const *restrict Q);

void *eddsa_point_dec(
    EdDSA_Ctx_Hdr_t *restrict x,
    uint8_t const buf[restrict],
    ecEd_xytz_t *restrict Q);

#endif /* MySuiteA_eddsa_misc_h */
