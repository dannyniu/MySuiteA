/* DannyNiu/NJF, 2022-02-05. Public Domain. */

#include "secp-imod-aux.h"

static const VLONG_T(8) Fp_secp256r1 = {
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

static const VLONG_T(12) Fp_secp384r1 = {
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

static vlong_t *secp256r1_remv_inplace(vlong_t *rem, void const *aux)
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

    for(t=0; t<p.c; t++) p.v[t] = Fp_secp256r1.v[t];
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

static vlong_t *secp384r1_remv_inplace(vlong_t *rem, void const *aux)
{
    static_assert(
        sizeof(*rem->v) == sizeof(uint32_t),
        "Data type assumption failed");
    
    vlong_size_t t;
    int64_t b;

    VLONG_T(12) p = VLONG_INIT(12);
    uint32_t u, v;
    int res = 0, mask;

    aux = NULL; // silence the unused argument warning.

    // avoid redundand and potentially erroneous computation.
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

    for(t=0; t<p.c; t++) p.v[t] = Fp_secp384r1.v[t];
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

static const ecp_imod_aux_t secp256r1_remv_callback = {
    .modfunc = (vlong_modfunc_t)secp256r1_remv_inplace,
    .mod_ctx = (vlong_t *)&Fp_secp256r1,
};

static const ecp_imod_aux_t secp384r1_remv_callback = {
    .modfunc = (vlong_modfunc_t)secp384r1_remv_inplace,
    .mod_ctx = (vlong_t *)&Fp_secp384r1,
};

const ecp_imod_aux_t *secp256r1_imod_aux = &secp256r1_remv_callback;
const ecp_imod_aux_t *secp384r1_imod_aux = &secp384r1_remv_callback;
