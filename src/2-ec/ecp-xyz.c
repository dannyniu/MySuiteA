/* DannyNiu/NJF, 2021-12-27. Public Domain. */

#include "ecp-xyz.h"
#include "../0-exec/struct-delta.c.h"

// 2022-02-05:
// Rewritten based on https://ia.cr/2015/1060

ecp_xyz_t *ecp_point_add_rcb15(
    ecp_xyz_t *restrict out,
    ecp_xyz_t const *p1,
    ecp_xyz_t const *p2,
    ecp_opctx_t *restrict opctx,
    ecp_curve_t const *restrict curve)
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
    vlong_t *t0 = DeltaTo(opctx, offset_r);
    vlong_t *t1 = DeltaTo(opctx, offset_s);
    vlong_t *t2 = DeltaTo(opctx, offset_t);
    vlong_t *t3 = DeltaTo(opctx, offset_u);
    vlong_t *t4 = DeltaTo(opctx, offset_v);
    vlong_t *t5 = DeltaTo(opctx, offset_w);
    ecp_imod_aux_t const *aux = curve->imod_aux;

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
    vlong_imuls(z, t4, curve->a, false); // Z3 occupied.
    ecp_imod_inplace(z, aux);
    vlong_mulv_masked(x, curve->b, t2, 1, aux->modfunc, aux->mod_ctx);
    vlong_imuls(x, x, 3, false);
    // no need to: aux->modfunc(x, aux->mod_ctx); as x'll be overwritten soon.
    vlong_addv(z, x, z);
    aux->modfunc(z, aux->mod_ctx);

    // 22. 23. 24.
    vlong_subv(x, t1, z);
    ecp_imod_inplace(x, aux);
    vlong_addv(z, t1, z);
    vlong_mulv_masked(y, x, z, 1, aux->modfunc, aux->mod_ctx); // Y3 occupied.

    // 25. 26. 27.
    vlong_imuls(t1, t0, 3, false);
    aux->modfunc(t1, aux->mod_ctx);
    vlong_imuls(t2, t2, curve->a, false);
    ecp_imod_inplace(t2, aux);

    // skip 28. for now to spare a working variable.
    // 29. 30. 31.
    vlong_addv(t1, t1, t2);
    aux->modfunc(t1, aux->mod_ctx);
    vlong_subv(t2, t0, t2);
    ecp_imod_inplace(t2, aux);
    vlong_imuls(t2, t2, curve->a, false);
    ecp_imod_inplace(t2, aux);

    // 28. 32.
    vlong_mulv_masked(t0, t4, curve->b, 1, aux->modfunc, aux->mod_ctx);
    vlong_imuls(t4, t0, 3, false);
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
    ecp_opctx_t *restrict opctx,
    ecp_curve_t const *restrict curve)
{
    vlong_t *x = DeltaTo(out, offset_x);
    vlong_t *y = DeltaTo(out, offset_y);
    vlong_t *z = DeltaTo(out, offset_z);
    vlong_t const *x1 = DeltaTo(p1, offset_x);
    vlong_t const *y1 = DeltaTo(p1, offset_y);
    vlong_t const *z1 = DeltaTo(p1, offset_z);
    vlong_t *s = DeltaTo(opctx, offset_s);
    vlong_t *t = DeltaTo(opctx, offset_t);
    vlong_t *w = DeltaTo(opctx, offset_u);
    ecp_imod_aux_t const *aux = curve->imod_aux;

    vlong_mulv_masked(w, x1, x1, 1, aux->modfunc, aux->mod_ctx);
    vlong_muls(w, w, 3, false);
    ecp_imod_inplace(w, aux);
    vlong_mulv_masked(t, z1, z1, 1, aux->modfunc, aux->mod_ctx);
    vlong_imuls(s, t, curve->a, false);
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

    t = DeltaTo(p, offset_z);
    for(i=0; i<t->c; i++) t->v[i] = 0;

    t = DeltaTo(p, offset_y);
    t->v[0] = 1;
    for(i=1; i<t->c; i++) t->v[i] = 0;
}

static void ecp_xyz_substitute(
    ecp_xyz_t *restrict a,
    ecp_xyz_t const *restrict b,
    uint32_t mask)
{
    // it is assumed that mask is either 1 or 0.
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

        ecp_point_add_rcb15(tmp2, tmp1, accum, opctx, curve);
        ecp_xyz_substitute(accum, tmp2, mask);

        if( ++i >= f ) break;

        ecp_point_dbl_fast(tmp2, tmp1, opctx, curve);
        t = tmp2, tmp2 = tmp1, tmp1 = t;

        continue;
    }

    return accum;
}

vlong_t *vlong_sqrt_c3m4(
    vlong_t *restrict out,
    vlong_t const *x,
    vlong_t *restrict tmp1, // temporary variables are
    vlong_t *restrict tmp2, // allocated by the caller
    const ecp_imod_aux_t *restrict aux)
{
    if( (aux->mod_ctx->v[0] & 3) != 3 )
        return NULL;

    return vlong_modexpv_shiftadded(
        out, x, tmp1, tmp2,
        aux->modfunc, aux->mod_ctx, 1, 2);
}

vlong_t *vlong_inv_mod_p_fermat(
    vlong_t *restrict out,
    vlong_t const *x,
    vlong_t *restrict tmp1,
    vlong_t *restrict tmp2,
    ecp_curve_t const *restrict curve)
{
    return vlong_modexpv_shiftadded(
        out, x, tmp1, tmp2,
        curve->imod_aux->modfunc,
        curve->imod_aux->mod_ctx, -2, 0);
}

vlong_t *vlong_inv_mod_n_fermat(
    vlong_t *restrict out,
    vlong_t const *x,
    vlong_t *restrict tmp1,
    vlong_t *restrict tmp2,
    ecp_curve_t const *restrict curve)
{
    return vlong_modexpv_shiftadded(
        out, x, tmp1, tmp2,
        (vlong_modfunc_t)vlong_remv_inplace,
        curve->n, -2, 0);
}

void ecp_xyz_init(ecp_xyz_t *xyz, unsigned bits)
{
    *xyz = ECP_XYZ_HDR_INIT(bits);

    ((vlong_t *)DeltaTo(xyz, offset_x))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(xyz, offset_y))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(xyz, offset_z))->c = VLONG_BITS_WCNT(bits);
}

void ecp_opctx_init(ecp_opctx_t *opctx, unsigned bits)
{
    *opctx = ECP_OPCTX_HDR_INIT(bits);

    ((vlong_t *)DeltaTo(opctx, offset_r))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_s))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_t))->c = VLONG_BITS_WCNT(bits);

    ((vlong_t *)DeltaTo(opctx, offset_u))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_v))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_w))->c = VLONG_BITS_WCNT(bits);
}
