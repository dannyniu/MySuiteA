/* DannyNiu/NJF, 2022-04-16. Public Domain. */

#include "curveSM2.h"

static const VLONG_T(8) Fp = {
    .c = 8,
    .v[7] = -2,
    .v[6] = -1,
    .v[5] = -1,
    .v[4] = -1,
    .v[3] = -1,
    .v[2] = 0,
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

    (void)aux; // silence the unused argument warning.

    // avoid redundant and potentially erroneous computation.
    if( rem->c < 8 ) return rem;

    for(t = rem->c; t-- > 8; )
    {
        b = rem->v[t];
        rem->v[t] = 0;
        vlong_adds(rem, rem, b, t-1);
        vlong_adds(rem, rem, b, t-5);
        vlong_adds(rem, rem, -b, t-6);
        vlong_adds(rem, rem, b, t-8);

        b = rem->v[t];
        rem->v[t] = 0;
        vlong_adds(rem, rem, b, t-1);
        vlong_adds(rem, rem, b, t-5);
        vlong_adds(rem, rem, -b, t-6);
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
    .v[7] = 0x28E9FA9E,
    .v[6] = 0x9D9F5E34,
    .v[5] = 0x4D5A9E4B,
    .v[4] = 0xCF6509A7,
    .v[3] = 0xF39789F5,
    .v[2] = 0x15AB8F92,
    .v[1] = 0xDDBCBD41,
    .v[0] = 0x4D940E93,
};

static const VLONG_T(8) CrvParam_n = {
    .c = 8,
    .v[7] = -2,
    .v[6] = -1,
    .v[5] = -1,
    .v[4] = -1,
    .v[3] = 0x7203DF6B,
    .v[2] = 0x21C6052B,
    .v[1] = 0x53BBF409,
    .v[0] = 0x39D54123,
};

static const ecp256_xyz_t G = ECP256_XYZ_INIT(
    .x.v[7] = 0x32C4AE2C,
    .x.v[6] = 0x1F198119,
    .x.v[5] = 0x5F990446,
    .x.v[4] = 0x6A39C994,
    .x.v[3] = 0x8FE30BBF,
    .x.v[2] = 0xF2660BE1,
    .x.v[1] = 0x715A4589,
    .x.v[0] = 0x334C74C7,

    .y.v[7] = 0xBC3736A2,
    .y.v[6] = 0xF4F6779C,
    .y.v[5] = 0x59BDCEE3,
    .y.v[4] = 0x6B692153,
    .y.v[3] = 0xD0A9877C,
    .y.v[2] = 0xC62A4740,
    .y.v[1] = 0x02DF32E5,
    .y.v[0] = 0x2139F0A0,

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

const ecp_curve_t *curveSM2 = &CurveDef;

IntPtr i_curveSM2(int q) { return x_curveSM2(q); }
