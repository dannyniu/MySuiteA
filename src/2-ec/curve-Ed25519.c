
/* DannyNiu/NJF, 2022-05-05. Public Domain. */

#include "curves-Ed.h"

#define Fp Fp_25519
#define modp_aux modp25519_aux

extern const VLONG_T(8) Fp;
extern const ecp_imod_aux_t modp_aux;

static const VLONG_T(8) L = {
    .c = 8,
    .v[7] = 0x10000000,
    .v[6] = 0,
    .v[5] = 0,
    .v[4] = 0,
    .v[3] = 0x14def9de,
    .v[2] = 0xa2f79cd6,
    .v[1] = 0x5812631a,
    .v[0] = 0x5cf5d3ed,
};

static const ecEd256_xytz_t B = ECED256_XYTZ_INIT(
    .x.v[7] = 0x216936d3,
    .x.v[6] = 0xcd6e53fe,
    .x.v[5] = 0xc0a4e231,
    .x.v[4] = 0xfdd6dc5c,
    .x.v[3] = 0x692cc760,
    .x.v[2] = 0x9525a7b2,
    .x.v[1] = 0xc9562d60,
    .x.v[0] = 0x8f25d51a,

    .y.v[7] = 0x66666666,
    .y.v[6] = 0x66666666,
    .y.v[5] = 0x66666666,
    .y.v[4] = 0x66666666,
    .y.v[3] = 0x66666666,
    .y.v[2] = 0x66666666,
    .y.v[1] = 0x66666666,
    .y.v[0] = 0x66666658,

    .t.v[7] = 0x67875f0f,
    .t.v[6] = 0xd78b7665,
    .t.v[5] = 0x66ea4e8e,
    .t.v[4] = 0x64abe37d,
    .t.v[3] = 0x20f09f80,
    .t.v[2] = 0x775152f5,
    .t.v[1] = 0x6dde8ab3,
    .t.v[0] = 0xa5b7dda3,

    .z.v[0] = 1,
    );

static const ecEd_curve_t CurveDef = {
    .pbits      = 255,
    .a          = -1,
    .c          = 3,
    .d_over     = -121665,
    .d_under    = 121666,
    .p          = (const vlong_t *)&Fp,
    .L          = (const vlong_t *)&L,
    .B          = (const ecEd_xytz_t *)&B,
    .imod_aux   = &modp_aux,
};

const ecEd_curve_t *CurveEd25519 = &CurveDef;

IntPtr iCurveEd25519(int q) { return xCurveEd25519(q); }
