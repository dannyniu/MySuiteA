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

// 2021-12-27:
// <s>Based on the blueprint laid out in "ECC-Registers.txt".</s>
//
// 2022-02-05:
// Rewritten based on https://ia.cr/2015/1060

ecp_xyz_t *ecp_point_add_rcb15(
    ecp_xyz_t *restrict out,
    ecp_xyz_t const *p1,
    ecp_xyz_t const *p2,
    int32_t a,
    vlong_t *restrict b,
    ecp_opctx_t *restrict ctx,
    const ecp_imod_aux_t *restrict aux)
{
    // Algorithm 1 of the paper.
    
    vlong_t *x = DeltaTo(out, offset_x);
    vlong_t *y = DeltaTo(out, offset_y);
    vlong_t *z = DeltaTo(out, offset_z);
    vlong_t const *x1 = DeltaTo(p1, offset_x);
    vlong_t const *y1 = DeltaTo(p1, offset_y);
    vlong_t const *z1 = DeltaTo(p1, offset_z);
    vlong_t const *x2 = DeltaTo(p2, offset_x);
    vlong_t const *y2 = DeltaTo(p2, offset_y);
    vlong_t const *z2 = DeltaTo(p2, offset_z);
    vlong_t *t0 = DeltaTo(ctx, offset_r);
    vlong_t *t1 = DeltaTo(ctx, offset_s);
    vlong_t *t2 = DeltaTo(ctx, offset_t);
    vlong_t *t3 = DeltaTo(ctx, offset_u);
    vlong_t *t4 = DeltaTo(ctx, offset_v);
    vlong_t *t5 = DeltaTo(ctx, offset_w);

    // 1. 2. 3. 
    vlong_mulv_masked(t0, x1, x2, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(t1, y1, y2, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(t2, z1, z2, 1, aux->modfunc, aux->mod_ctx);

    // 4. 5. 6.
    vlong_addv(t3, x1, y1);
    aux->modfunc(t3, aux->mod_ctx);
    vlong_addv(t4, x2, y2); // t4 evaluated once but not mod'd.
    vlong_mulv_masked(t5, t3, t4, 1, aux->modfunc, aux->mod_ctx);
    vlong_cpy(t3, t5);

    // 7. 8. 9.
    vlong_addv(t4, t0, t1);
    aux->modfunc(t4, aux->mod_ctx);
    vlong_subv(t3, t3, t4);
    ecp_imod_inplace(t3, aux);
    vlong_addv(t4, x1, z1);
    aux->modfunc(t4, aux->mod_ctx);

    // 10. 11. 12.
    vlong_addv(t5, x2, z2);
    aux->modfunc(t5, aux->mod_ctx);
    vlong_mulv_masked(x, t4, t5, 1, aux->modfunc, aux->mod_ctx);
    vlong_cpy(t4, x);
    vlong_addv(t5, t0, t2);
    aux->modfunc(t5, aux->mod_ctx);

    // 13. 14. 15.
    vlong_subv(t4, t4, t5);
    ecp_imod_inplace(t4, aux);
    vlong_addv(t5, y1, z1);
    aux->modfunc(t5, aux->mod_ctx);
    vlong_addv(x, y2, z2); // X3 occupied.
    aux->modfunc(x, aux->mod_ctx);

    // 16. 17. 18.
    vlong_mulv_masked(y, t5, x, 1, aux->modfunc, aux->mod_ctx);
    vlong_cpy(t5, y);
    vlong_addv(x, t1, t2);
    aux->modfunc(x, aux->mod_ctx);
    vlong_subv(t5, t5, x);
    ecp_imod_inplace(t5, aux);

    // 19. 20. 21.
    vlong_imuls(z, t4, a); // Z3 occupied.
    ecp_imod_inplace(z, aux);
    vlong_mulv_masked(x, b, t2, 1, aux->modfunc, aux->mod_ctx);
    vlong_imuls(x, x, 3);
    // no need to: aux->modfunc(x, aux->mod_ctx); as x'll be overwritten soon.
    vlong_addv(z, x, z);
    aux->modfunc(z, aux->mod_ctx);

    // 22. 23. 24.
    vlong_subv(x, t1, z);
    ecp_imod_inplace(x, aux);
    vlong_addv(z, t1, z);
    vlong_mulv_masked(y, x, z, 1, aux->modfunc, aux->mod_ctx); // Y3 occupied.

    // 25. 26. 27.
    vlong_imuls(t1, t0, 3);
    aux->modfunc(t1, aux->mod_ctx);
    vlong_imuls(t2, t2, a);
    ecp_imod_inplace(t2, aux);

    // skip 28. for now to spare a working variable.
    // 29. 30. 31.
    vlong_addv(t1, t1, t2);
    aux->modfunc(t1, aux->mod_ctx);
    vlong_subv(t2, t0, t2);
    ecp_imod_inplace(t2, aux);
    vlong_imuls(t2, t2, a);
    ecp_imod_inplace(t2, aux);

    // 28. 32.
    vlong_mulv_masked(t0, t4, b, 1, aux->modfunc, aux->mod_ctx);
    vlong_imuls(t4, t0, 3);
    vlong_addv(t4, t4, t2);
    aux->modfunc(t4, aux->mod_ctx);

    // 33. 34.
    vlong_mulv_masked(t0, t1, t4, 1, aux->modfunc, aux->mod_ctx);
    vlong_addv(y, y, t0);
    aux->modfunc(y, aux->mod_ctx);

    // 36. 35. 37.
    vlong_mulv_masked(t0, t3, x, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(x, t5, t4, 1, aux->modfunc, aux->mod_ctx);
    vlong_subv(x, t0, x);
    ecp_imod_inplace(x, aux);

    // 39. 38. 40.
    vlong_mulv_masked(t0, t5, z, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(z, t3, t1, 1, aux->modfunc, aux->mod_ctx);
    vlong_addv(z, t0, z);
    aux->modfunc(z, aux->mod_ctx);

    return out;
}

ecp_xyz_t *ecp_point_dbl_fast(
    ecp_xyz_t *restrict out,
    ecp_xyz_t const *p1,
    int32_t a,
    ecp_opctx_t *restrict ctx,
    const ecp_imod_aux_t *restrict aux)
{
    vlong_t *x = DeltaTo(out, offset_x);
    vlong_t *y = DeltaTo(out, offset_y);
    vlong_t *z = DeltaTo(out, offset_z);
    vlong_t const *x1 = DeltaTo(p1, offset_x);
    vlong_t const *y1 = DeltaTo(p1, offset_y);
    vlong_t const *z1 = DeltaTo(p1, offset_z);
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
