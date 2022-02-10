/* DannyNiu/NJF, 2022-02-05. Public Domain. */

#include "curves-secp.h"

static const VLONG_T(8) Fp = {
    .c = 8,
    .v[7] = -1,
    .v[6] = 1,
    .v[5] = 0,
    .v[4] = 0,
    .v[3] = 0,
    .v[2] = -1,
    .v[1] = -1,
    .v[0] = -1,
};

static vlong_t *remv_inplace(vlong_t *rem, void const *aux)
{
    static_assert(
        sizeof(*rem->v) == sizeof(uint32_t),
        "Data type assumption failed");
    
    vlong_size_t t;
    int64_t b;

    VLONG_T(8) p = VLONG_INIT(8);
    uint32_t u, v;
    int res = 0, mask;

    aux = NULL; // silence the unused argument warning.

    // avoid redundand and potentially erroneous computation.
    if( rem->c < 8 ) return rem;

    for(t = rem->c; t-- > 8; )
    {
        b = rem->v[t];
        rem->v[t] = 0;
        vlong_adds(rem, rem, b, t-1);
        vlong_adds(rem, rem, -b, t-2);
        vlong_adds(rem, rem, -b, t-5);
        vlong_adds(rem, rem, b, t-8);
        
        b = rem->v[t];
        rem->v[t] = 0;
        vlong_adds(rem, rem, b, t-1);
        vlong_adds(rem, rem, -b, t-2);
        vlong_adds(rem, rem, -b, t-5);
        vlong_adds(rem, rem, b, t-8);
    }

    for(t=0; t<p.c; t++) p.v[t] = Fp.v[t];
    for(t = rem->c; t--; )
    {
        u = rem->v[t];
        v = t < p.c ? p.v[t] : 0;
        mask = (1 & ((res >> 1) | res)) * 3;
        mask = ~mask;
        mask &= vlong_cmps(u, v);
        res |= mask;
    }

    u = ((res ^ 1) - 1) >> 8;
    u = -(u & 1);

    for(t=0; t<p.c; t++) p.v[t] &= u;
    vlong_subv(rem, rem, (void *)&p);

    return rem;
}

static const ecp_imod_aux_t remv_callback = {
    .modfunc = (vlong_modfunc_t)remv_inplace,
    .mod_ctx = (vlong_t *)&Fp,
};

static const VLONG_T(8) CrvEq_b = {
    .c = 8,
    .v[7] = 0x5AC635D8,
    .v[6] = 0xAA3A93E7,
    .v[5] = 0xB3EBBD55,
    .v[4] = 0x769886BC,
    .v[3] = 0x651D06B0,
    .v[2] = 0xCC53B0F6,
    .v[1] = 0x3BCE3C3E,
    .v[0] = 0x27D2604B,
};

static const VLONG_T(8) CrvParam_n = {
    .c = 8,
    .v[7] = -1,
    .v[6] = 0,
    .v[5] = -1,
    .v[4] = -1,
    .v[3] = 0xBCE6FAAD,
    .v[2] = 0xA7179E84,
    .v[1] = 0xF3B9CAC2,
    .v[0] = 0xFC632551,
};

static const ecp256_xyz_t G = ECP256_XYZ_INIT(
    .x.v[7] = 0x6B17D1F2,
    .x.v[6] = 0xE12C4247,
    .x.v[5] = 0xF8BCE6E5,
    .x.v[4] = 0x63A440F2,
    .x.v[3] = 0x77037D81,
    .x.v[2] = 0x2DEB33A0,
    .x.v[1] = 0xF4A13945,
    .x.v[0] = 0xD898C296,
    
    .y.v[7] = 0x4FE342E2,
    .y.v[6] = 0xFE1A7F9B,
    .y.v[5] = 0x8EE7EB4A,
    .y.v[4] = 0x7C0F9E16,
    .y.v[3] = 0x2BCE3357,
    .y.v[2] = 0x6B315ECE,
    .y.v[1] = 0xCBB64068,
    .y.v[0] = 0x37BF51F5,
    
    .z.v[0] = 1,
    );

static const ecp_curve_t CurveDef = {
    .plen = 32,
    .h = 1,
    .a = -3,
    .b = (vlong_t *)&CrvEq_b,
    .p = (vlong_t *)&Fp,
    .n = (vlong_t *)&CrvParam_n,
    .G = (ecp_xyz_t *)&G,
    .imod_aux = &remv_callback,
};

const ecp_curve_t *secp256r1 = &CurveDef;

IntPtr i_secp256r1(int q) { return x_secp256r1(q); }
