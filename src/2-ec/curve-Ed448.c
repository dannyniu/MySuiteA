
/* DannyNiu/NJF, 2022-05-05. Public Domain. */

#include "curves-Ed.h"

#define Fp Fp_448
#define modp_aux modp448_aux

extern const VLONG_T(14) Fp;
extern const ecp_imod_aux_t modp_aux;

static const VLONG_T(14) L = {
    .c = 14,
    .v[13] = 0x3fffffff,
    .v[12] = -1,
    .v[11] = -1,
    .v[10] = -1,
    .v[9] = -1,
    .v[8] = -1,
    .v[7] = -1,
    .v[6] = 0x7cca23e9,
    .v[5] = 0xc44edb49,
    .v[4] = 0xaed63690,
    .v[3] = 0x216cc272,
    .v[2] = 0x8dc58f55,
    .v[1] = 0x2378c292,
    .v[0] = 0xab5844f3
};

static const ecEd448_xytz_t B = ECED448_XYTZ_INIT(
    .x.v[13] = 0x4f1970c6,
    .x.v[12] = 0x6bed0ded,
    .x.v[11] = 0x221d15a6,
    .x.v[10] = 0x22bf36da,
    .x.v[9] = 0x9e146570,
    .x.v[8] = 0x470f1767,
    .x.v[7] = 0xea6de324,
    .x.v[6] = 0xa3d3a464,
    .x.v[5] = 0x12ae1af7,
    .x.v[4] = 0x2ab66511,
    .x.v[3] = 0x433b80e1,
    .x.v[2] = 0x8b00938e,
    .x.v[1] = 0x2626a82b,
    .x.v[0] = 0xc70cc05e,

    .y.v[13] = 0x693f4671,
    .y.v[12] = 0x6eb6bc24,
    .y.v[11] = 0x88762037,
    .y.v[10] = 0x56c9c762,
    .y.v[9] = 0x4bea7373,
    .y.v[8] = 0x6ca39840,
    .y.v[7] = 0x87789c1e,
    .y.v[6] = 0x05a0c2d7,
    .y.v[5] = 0x3ad3ff1c,
    .y.v[4] = 0xe67c39c4,
    .y.v[3] = 0xfdbd132c,
    .y.v[2] = 0x4ed7c8ad,
    .y.v[1] = 0x9808795b,
    .y.v[0] = 0xf230fa14,

    .t.v[13] = 0xc75eb58a,
    .t.v[12] = 0xee221c6c,
    .t.v[11] = 0xcec39d2d,
    .t.v[10] = 0x508d91c9,
    .t.v[9] = 0xc5056a18,
    .t.v[8] = 0x3f8451d2,
    .t.v[7] = 0x60d71667,
    .t.v[6] = 0xe2356d58,
    .t.v[5] = 0xf179de90,
    .t.v[4] = 0xb5b27da1,
    .t.v[3] = 0xf78fa07d,
    .t.v[2] = 0x85662d1d,
    .t.v[1] = 0xeb06624e,
    .t.v[0] = 0x82af95f3,

    .z.v[0] = 1,
    );

static const ecEd_curve_t CurveDef = {
    .pbits      = 448,
    .a          = 1,
    .c          = 2,
    .d_over     = -39081,
    .d_under    = 1,
    .p          = (const vlong_t *)&Fp,
    .L          = (const vlong_t *)&L,
    .B          = (const ecEd_xytz_t *)&B,
    .imod_aux   = &modp_aux,
};

const ecEd_curve_t *CurveEd448 = &CurveDef;

IntPtr iCurveEd448(int q) { return xCurveEd448(q); }
