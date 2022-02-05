/* DannyNiu/NJF, 2021-12-27. Public Domain. */

#include "ecp-xyz.h"
#include "../0-exec/struct-delta.c.h"

vlong_t *ecp_imod_inplace(vlong_t *rem, const ecp_imod_aux_t *aux)
{
    vlong_size_t i;
    uint32_t neg = -((rem->v[rem->c - 1] >> 31) & 1);
    uint32_t z = 0;
    uint64_t x = 0;

    // the following line is a addition for
    // elliptic-curve cryptography.
    const vlong_t *b = aux->mod_ctx;

    // imod(x,p) := x >= 0 ? x % p : (p - (-x % p));
    
    for(i=0; i<rem->c; i++) rem->v[i] ^= neg;
    vlong_adds(rem, rem, neg&1, 0);

    aux->modfunc(rem, aux->mod_ctx);

    for(i=0; i<rem->c; i++) z |= rem->v[i];
    
    // Per suggestion by @fgrieu at https://crypto.stackexchange.com/q/88233
    z |= z >> 16;
    z &= 0xffffU;
    z = -(1 ^ ((z ^ (z - 1)) >> 31));
    neg &= z;

    for(i=0; i<rem->c; i++)
    {
        uint32_t u, v;
        u = i < rem->c ? rem->v[i] : 0;
        v = i <   b->c ?   b->v[i] : 0;
        
        x += (~neg & u) | (neg & v);
        x -= (neg & u);
        rem->v[i] = (uint32_t)x;
        
        x >>= 32;
        x = (uint64_t)(int64_t)(int32_t)x;
    }
    return rem;
}

// 2021-12-27:
// Based on the blueprint laid out in "ECC-Registers.txt".

ecp_xyz_t *ecp_point_add(
    ecp_xyz_t *out,
    ecp_xyz_t const *p1,
    ecp_xyz_t const *p2,
    ecp_opctx_t *ctx,
    const ecp_imod_aux_t *aux)
{
    vlong_t *x = DeltaTo(out, offset_x);
    vlong_t *y = DeltaTo(out, offset_y);
    vlong_t *z = DeltaTo(out, offset_z);
    vlong_t *x1 = DeltaTo(p1, offset_x);
    vlong_t *y1 = DeltaTo(p1, offset_y);
    vlong_t *z1 = DeltaTo(p1, offset_z);
    vlong_t *x2 = DeltaTo(p2, offset_x);
    vlong_t *y2 = DeltaTo(p2, offset_y);
    vlong_t *z2 = DeltaTo(p2, offset_z);
    vlong_t *s = DeltaTo(ctx, offset_s);
    vlong_t *t = DeltaTo(ctx, offset_t);
    vlong_t *u = DeltaTo(ctx, offset_u);
    vlong_t *v = DeltaTo(ctx, offset_v);

    vlong_mulv_masked(u, y2, z1, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(t, y1, z2, 1, aux->modfunc, aux->mod_ctx);
    vlong_subv(u, u, t);
    ecp_imod_inplace(u, aux);
    vlong_mulv_masked(v, x2, z1, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(t, x1, z2, 1, aux->modfunc, aux->mod_ctx);
    vlong_subv(v, v, t);
    ecp_imod_inplace(v, aux);

    vlong_mulv_masked(t, u, u, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(x, t, z1, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(t, v, v, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, t, x1, 1, aux->modfunc, aux->mod_ctx);
    vlong_muls(s, s, 2, false);
    aux->modfunc(s, aux->mod_ctx);
    //ecp_imod_inplace(s, aux);
    vlong_subv(x, x, s);
    ecp_imod_inplace(x, aux);
    vlong_mulv_masked(t, x, z2, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, v, v, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(x, s, v, 1, aux->modfunc, aux->mod_ctx);
    vlong_subv(t, t, x);
    ecp_imod_inplace(t, aux);
    vlong_mulv_masked(x, t, v, 1, aux->modfunc, aux->mod_ctx);
    
    vlong_mulv_masked(t, v, v, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, t, u, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(y, s, x1, 1, aux->modfunc, aux->mod_ctx);
    vlong_muls(y, y, 3, false);
    aux->modfunc(y, aux->mod_ctx);
    //ecp_imod_inplace(y, aux);
    vlong_mulv_masked(s, t, v, 1, aux->modfunc, aux->mod_ctx);
    vlong_adds(v, s, 0, false);
    vlong_mulv_masked(t, v, y1, 1, aux->modfunc, aux->mod_ctx);
    vlong_subv(y, y, t);
    ecp_imod_inplace(y, aux);
    vlong_mulv_masked(t, u, u, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, t, u, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(t, s, z1, 1, aux->modfunc, aux->mod_ctx);
    vlong_subv(y, y, t);
    ecp_imod_inplace(y, aux);
    vlong_mulv_masked(t, y, z2, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(y, u, v, 1, aux->modfunc, aux->mod_ctx);
    vlong_addv(y, t, y);
    ecp_imod_inplace(y, aux);

    vlong_mulv_masked(t, v, z1, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(z, t, z2, 1, aux->modfunc, aux->mod_ctx);

    return out;
}

static vlong_t *vlong_imuls(vlong_t *out, vlong_t const *a, int64_t b)
{
    vlong_size_t i;
    uint64_t x;

    for(i=0, x=0; i<out->c; i++)
    {
        x += i < a->c ? a->v[i] * (uint64_t)b : 0;
        out->v[i] = (uint32_t)x;
        x = (uint64_t)(int64_t)(int32_t)(x >> 32);
    }

    return out;
}

ecp_xyz_t *ecp_point_dbl(
    ecp_xyz_t *out,
    ecp_xyz_t const *p1,
    int32_t a,
    ecp_opctx_t *ctx,
    const ecp_imod_aux_t *aux)
{
    vlong_t *x = DeltaTo(out, offset_x);
    vlong_t *y = DeltaTo(out, offset_y);
    vlong_t *z = DeltaTo(out, offset_z);
    vlong_t *x1 = DeltaTo(p1, offset_x);
    vlong_t *y1 = DeltaTo(p1, offset_y);
    vlong_t *z1 = DeltaTo(p1, offset_z);
    vlong_t *s = DeltaTo(ctx, offset_s);
    vlong_t *t = DeltaTo(ctx, offset_t);
    vlong_t *w = DeltaTo(ctx, offset_u);

    vlong_mulv_masked(w, x1, x1, 1, aux->modfunc, aux->mod_ctx);
    vlong_muls(w, w, 3, false);
    ecp_imod_inplace(w, aux);
    vlong_mulv_masked(t, z1, z1, 1, aux->modfunc, aux->mod_ctx);
    vlong_imuls(s, t, a);
    ecp_imod_inplace(s, aux);
    vlong_addv(w, w, s);
    aux->modfunc(w, aux->mod_ctx);
    //ecp_imod_inplace(w, aux);

    vlong_mulv_masked(y, w, x1, 1, aux->modfunc, aux->mod_ctx);
    vlong_muls(y, y, 3, false);
    aux->modfunc(y, aux->mod_ctx);
    //ecp_imod_inplace(y, aux);
    vlong_mulv_masked(t, y1, y1, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, t, z1, 1, aux->modfunc, aux->mod_ctx);
    vlong_muls(s, s, 2, false);
    aux->modfunc(s, aux->mod_ctx);
    //ecp_imod_inplace(s, aux);
    vlong_subv(y, y, s);
    ecp_imod_inplace(y, aux);
    vlong_mulv_masked(s, y, t, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(y, s, z1, 1, aux->modfunc, aux->mod_ctx);
    vlong_muls(y, y, 4, false);
    aux->modfunc(y, aux->mod_ctx);
    //ecp_imod_inplace(y, aux);

    vlong_mulv_masked(s, t, z1, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(x, s, x1, 1, aux->modfunc, aux->mod_ctx);
    vlong_muls(x, x, 8, false);
    aux->modfunc(x, aux->mod_ctx);
    //ecp_imod_inplace(x, aux);
    vlong_mulv_masked(s, w, w, 1, aux->modfunc, aux->mod_ctx);
    vlong_subv(x, s, x);
    ecp_imod_inplace(x, aux);
    
    vlong_mulv_masked(t, s, w, 1, aux->modfunc, aux->mod_ctx);
    vlong_subv(y, y, t);
    ecp_imod_inplace(y, aux);
    
    vlong_mulv_masked(t, y1, z1, 1, aux->modfunc, aux->mod_ctx);
    vlong_muls(s, x, 2, false);
    aux->modfunc(s, aux->mod_ctx);
    //ecp_imod_inplace(s, aux);
    vlong_mulv_masked(x, t, s, 1, aux->modfunc, aux->mod_ctx);
    
    vlong_mulv_masked(s, t, t, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(z, s, t, 1, aux->modfunc, aux->mod_ctx);
    vlong_muls(z, z, 8, false);
    aux->modfunc(z, aux->mod_ctx);
    //ecp_imod_inplace(z, aux);

    return out;
}
