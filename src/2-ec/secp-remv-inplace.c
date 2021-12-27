/* DannyNiu/NJF, 2021-12-27. Public Domain. */

#include "secp-xyz.h"

vlong_t *secp256r1_remv_inplace(vlong_t *rem, void const *aux)
{
    static_assert(
        sizeof(*rem->v) == sizeof(uint32_t),
        "Data type assumption failed");
    
    vlong_size_t t;
    int64_t b;

    VLONG_T(8) p = {
        .c = 8,
        .v[7] = 0xffffffff,
        .v[6] = 1,
        .v[5] = 0,
        .v[4] = 0,
        .v[3] = 0,
        .v[2] = 0xffffffff,
        .v[1] = 0xffffffff,
        .v[0] = 0xffffffff,
    };
    
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

    for(t = rem->c; t--; )
    {
        u = rem->v[t];
        v = t < 8 ? p.v[t] : 0;
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

vlong_t *secp384r1_remv_inplace(vlong_t *rem, void const *aux)
{
    static_assert(
        sizeof(*rem->v) == sizeof(uint32_t),
        "Data type assumption failed");
    
    vlong_size_t t;
    int64_t b;

    VLONG_T(12) p = {
        .c = 12,
        .v[11] = 0xffffffff,
        .v[10] = 0xffffffff,
        .v[ 9] = 0xffffffff,
        .v[ 8] = 0xffffffff,
        .v[ 7] = 0xffffffff,
        .v[ 6] = 0xffffffff,
        .v[ 5] = 0xffffffff,
        .v[ 4] = 0xfffffffe,
        .v[ 3] = 0xffffffff,
        .v[ 2] = 0,
        .v[ 1] = 0,
        .v[ 0] = 0xffffffff,
    };
    
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

    for(t = rem->c; t--; )
    {
        u = rem->v[t];
        v = t < 12 ? p.v[t] : 0;
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
