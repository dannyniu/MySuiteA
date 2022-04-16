/* DannyNiu/NJF, 2022-02-06. Public Domain. */

#include "curves-secp.h"

static const VLONG_T(12) Fp = {
    .c = 12,
    .v[11] = -1,
    .v[10] = -1,
    .v[9] = -1,
    .v[8] = -1,
    .v[7] = -1,
    .v[6] = -1,
    .v[5] = -1,
    .v[4] = -2,
    .v[3] = -1,
    .v[2] = 0,
    .v[1] = 0,
    .v[0] = -1,
};

static vlong_t *remv_inplace(vlong_t *rem, void const *aux)
{
    static_assert(
        sizeof(*rem->v) == sizeof(uint32_t),
        "Data type assumption failed");
    
    vlong_size_t t;
    int64_t b;

    VLONG_T(12) p = VLONG_INIT(12);
    uint32_t u, v;
    int res = 0, mask;

    (void)aux; // silence the unused argument warning.

    // avoid redundant and potentially erroneous computation.
    if( rem->c < 12 ) return rem;

    for(t = rem->c; t-- > 12; )
    {
        b = rem->v[t];
        rem->v[t] = 0;
        vlong_adds(rem, rem, b, t-8);
        vlong_adds(rem, rem, b, t-9);
        vlong_adds(rem, rem, -b, t-11);
        vlong_adds(rem, rem, b, t-12);
        
        b = rem->v[t];
        rem->v[t] = 0;
        vlong_adds(rem, rem, b, t-8);
        vlong_adds(rem, rem, b, t-9);
        vlong_adds(rem, rem, -b, t-11);
        vlong_adds(rem, rem, b, t-12);
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

static const VLONG_T(12) CrvEq_b = {
    .c = 12,
    .v[11] = 0xB3312FA7,
    .v[10] = 0xE23EE7E4,
    .v[ 9] = 0x988E056B,
    .v[ 8] = 0xE3F82D19,
    .v[ 7] = 0x181D9C6E,
    .v[ 6] = 0xFE814112,
    .v[ 5] = 0x0314088F,
    .v[ 4] = 0x5013875A,
    .v[ 3] = 0xC656398D,
    .v[ 2] = 0x8A2ED19D,
    .v[ 1] = 0x2A85C8ED,
    .v[ 0] = 0xD3EC2AEF,
};

static const VLONG_T(12) CrvParam_n = {
    .c = 12,
    .v[11] = -1,
    .v[10] = -1,
    .v[ 9] = -1,
    .v[ 8] = -1,
    .v[ 7] = -1,
    .v[ 6] = -1,
    .v[ 5] = 0xC7634D81,
    .v[ 4] = 0xF4372DDF,
    .v[ 3] = 0x581A0DB2,
    .v[ 2] = 0x48B0A77A,
    .v[ 1] = 0xECEC196A,
    .v[ 0] = 0xCCC52973,
};

static const ecp384_xyz_t G = ECP384_XYZ_INIT(
    .x.v[11] = 0xAA87CA22,
    .x.v[10] = 0xBE8B0537,
    .x.v[ 9] = 0x8EB1C71E,
    .x.v[ 8] = 0xF320AD74,
    .x.v[ 7] = 0x6E1D3B62,
    .x.v[ 6] = 0x8BA79B98,
    .x.v[ 5] = 0x59F741E0,
    .x.v[ 4] = 0x82542A38,
    .x.v[ 3] = 0x5502F25D,
    .x.v[ 2] = 0xBF55296C,
    .x.v[ 1] = 0x3A545E38,
    .x.v[ 0] = 0x72760AB7,
    
    .y.v[11] = 0x3617DE4A,
    .y.v[10] = 0x96262C6F,
    .y.v[ 9] = 0x5D9E98BF,
    .y.v[ 8] = 0x9292DC29,
    .y.v[ 7] = 0xF8F41DBD,
    .y.v[ 6] = 0x289A147C,
    .y.v[ 5] = 0xE9DA3113,
    .y.v[ 4] = 0xB5F0B8C0,
    .y.v[ 3] = 0x0A60B1CE,
    .y.v[ 2] = 0x1D7E819D,
    .y.v[ 1] = 0x7A431D7C,
    .y.v[ 0] = 0x90EA0E5F,
    
    .z.v[0] = 1,
    );

static const ecp_curve_t CurveDef = {
    .plen = 48,
    .h = 1,
    .a = -3,
    .b = (vlong_t *)&CrvEq_b,
    .p = (vlong_t *)&Fp,
    .n = (vlong_t *)&CrvParam_n,
    .G = (ecp_xyz_t *)&G,
    .imod_aux = &remv_callback,
};

const ecp_curve_t *secp384r1 = &CurveDef;

IntPtr i_secp384r1(int q) { return x_secp384r1(q); }
