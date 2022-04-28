/* DannyNiu/NJF, 2022-04-27. Public Domain */

#include "ec-common.h"

static const VLONG_T(14) Fp = {
    .c = 14,
    .v[13] = -1,
    .v[12] = -1,
    .v[11] = -1,
    .v[10] = -1,
    .v[9] = -1,
    .v[8] = -1,
    .v[7] = -2,
    .v[6] = -1,
    .v[5] = -1,
    .v[4] = -1,
    .v[3] = -1,
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

    VLONG_T(14) p = VLONG_INIT(14);
    uint32_t u, v;
    int res = 0, mask;

    (void)aux; // silence the unused argument warning.

    // avoid redundant and potentially erroneous computation.
    if( rem->c < 14 ) return rem;

    for(t = rem->c; t-- > 14; )
    {
        b = rem->v[t];
        rem->v[t] = 0;
        vlong_adds(rem, rem, b, t-7);
        vlong_adds(rem, rem, b, t-14);

        b = rem->v[t];
        rem->v[t] = 0;
        vlong_adds(rem, rem, b, t-7);
        vlong_adds(rem, rem, b, t-14);
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

const ecp_imod_aux_t *modp448 = &remv_callback;
