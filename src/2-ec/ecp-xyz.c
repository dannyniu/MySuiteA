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

// 2022-02-05:
// Rewritten based on https://ia.cr/2015/1060

ecp_xyz_t *ecp_point_add_rcb15(
    ecp_xyz_t *restrict out,
    ecp_xyz_t const *p1,
    ecp_xyz_t const *p2,
    int32_t a,
    vlong_t const *restrict b,
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

// 2021-12-27:
// Based on the blueprint laid out in "ECC-Registers.txt".

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

void ecp_xyz_copy(
    ecp_xyz_t *restrict dst,
    ecp_xyz_t const *restrict src)
{
    vlong_cpy(DeltaTo(dst, offset_x), DeltaTo(src, offset_x));
    vlong_cpy(DeltaTo(dst, offset_y), DeltaTo(src, offset_y));
    vlong_cpy(DeltaTo(dst, offset_z), DeltaTo(src, offset_z));
}

void ecp_xyz_inf(ecp_xyz_t *p)
{
    vlong_t *t;
    vlong_size_t i;

    t = DeltaTo(p, offset_x);
    for(i=0; i<t->c; i++) t->v[i] = 0;
    
    t = DeltaTo(p, offset_y);
    for(i=0; i<t->c; i++) t->v[i] = 0;
    t->v[0] = 1;
    
    t = DeltaTo(p, offset_z);
    for(i=0; i<t->c; i++) t->v[i] = 0;
}

static void ecp_xyz_substitute(
    ecp_xyz_t *restrict a,
    ecp_xyz_t const *restrict b,
    uint32_t mask)
{
    // it is assumed that mask is either 1 or 2.
    // it uses the uint32_t type because of desiring its width.
    uint32_t bmask = -mask;
    uint32_t amask = ~bmask;

    vlong_t *v1, *v2;
    vlong_size_t i;

    v1 = DeltaTo(a, offset_x);
    v2 = DeltaTo(b, offset_x);
    for(i=0; i<v1->c; i++)
    {
        v1->v[i] =
            (amask & v1->v[i]) |
            (bmask & (i < v2->c ? v2->v[i] : 0));
    }

    v1 = DeltaTo(a, offset_y);
    v2 = DeltaTo(b, offset_y);
    for(i=0; i<v1->c; i++)
    {
        v1->v[i] =
            (amask & v1->v[i]) |
            (bmask & (i < v2->c ? v2->v[i] : 0));
    }

    v1 = DeltaTo(a, offset_z);
    v2 = DeltaTo(b, offset_z);
    for(i=0; i<v1->c; i++)
    {
        v1->v[i] =
            (amask & v1->v[i]) |
            (bmask & (i < v2->c ? v2->v[i] : 0));
    }
}    

ecp_xyz_t *ecp_point_scale_accumulate(
    ecp_xyz_t *restrict accum,
    ecp_xyz_t *restrict tmp1, // temporary variables are
    ecp_xyz_t *restrict tmp2, // allocated by the caller
    ecp_xyz_t const *restrict base,
    vlong_t const *restrict scalar,
    ecp_opctx_t *restrict opctx,
    ecp_curve_t const *restrict curve)
{
    ecp_xyz_t *t;
    vlong_size_t f, i;
    uint32_t mask;
    
    ecp_xyz_copy(tmp1, base);

    // 2022-02-06:
    // Setting the accumulation register to point at infinity should be
    // explicitly performed by the caller. Removing this step from the
    // function body allows a previously computed product to be reused
    // for further computation. The name of this function had also been
    // renamed appropriately (it was called "ecp_point_scl").
    //- ecp_xyz_inf(accum);

    f = scalar->c * 32;
    
    for(i=0;;)
    {
        mask = scalar->v[i / 32] >> (i % 32);
        mask &= 1;

        ecp_point_add_rcb15(
            tmp2, tmp1, accum,
            curve->a, curve->b,
            opctx, curve->imod_aux);

        ecp_xyz_substitute(accum, tmp2, mask);

        if( ++i >= f ) break;

        ecp_point_dbl_fast(
            tmp2, tmp1, curve->a,
            opctx, curve->imod_aux);

        t = tmp2, tmp2 = tmp1, tmp1 = t;

        continue;
    }

    return accum;
}

static vlong_t *vlong_inv_c3m4( // modular inversion mod prime p with p === 3 mod 4.
    vlong_t *restrict out,
    vlong_t const *x,
    vlong_t *restrict tmp1, // temporary variables are
    vlong_t *restrict tmp2, // allocated by the caller
    const ecp_imod_aux_t *restrict aux)
{
    vlong_size_t f, i, j, n;
    
    vlong_t const *e = aux->mod_ctx;
    uint64_t w = e->v[0] + 1;
    uint32_t mask;
    
    if( out->c != tmp1->c || tmp1->c != tmp2->c )
        return NULL;

    if( (e->v[0] & 3) != 3 )
        return NULL;

    f = e->c * 32;
    n = out->c;

    for(i=0; i<n; i++)
    {
        // 2021-06-05:
        // 2 statements re-ordered to ensure copy won't be inconsistent,
        // and that ``base'' can be reused (e.g. aliasing ``out'' to ``base'').
        // 2022-02-06:
        // ``base'' renamed to ``x''.
        tmp1->v[i] = i < x->c ? x->v[i] : 0;
        out->v[i] = i ? 0 : 1;
    }
    
    for(i=2;;) // i=2 <= exponent divided by 4.
    {
        if( i % 32 == 0 ) w = (w >> 32) + e->v[i / 32];
        mask = (w >> (i % 32)) & 1;

        vlong_mulv_masked(
            tmp2,
            out, tmp1,
            mask, aux->modfunc, aux->mod_ctx);

        for(j=0; j<n; j++) out->v[j] = tmp2->v[j];

        if( ++i >= f ) break;
        
        vlong_mulv_masked(
            tmp2,
            tmp1, tmp1,
            1, aux->modfunc, aux->mod_ctx);

        for(j=0; j<n; j++) tmp1->v[j] = tmp2->v[j];

        continue;
    }
    
    return out;
}
