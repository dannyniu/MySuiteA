/* DannyNiu/NJF, 2022-05-02. Public Domain. */

#include "ecEd.h"
#include "../0-exec/struct-delta.c.h"

ecEd_xytz_t *ecEd_point_add(
    ecEd_xytz_t *out, // intentionally not restrict-qualified,
    ecEd_xytz_t const *p1,
    ecEd_xytz_t const *p2,
    ecEd_opctx_t *restrict opctx,
    ecEd_curve_t const *restrict curve)
{
    ecp_imod_aux_t const *aux = curve->imod_aux;

    vlong_t const *x1 = DeltaTo(p1, offset_x);
    vlong_t const *y1 = DeltaTo(p1, offset_y);
    vlong_t const *t1 = DeltaTo(p1, offset_t);
    vlong_t const *z1 = DeltaTo(p1, offset_z);
    vlong_t const *x2 = DeltaTo(p2, offset_x);
    vlong_t const *y2 = DeltaTo(p2, offset_y);
    vlong_t const *t2 = DeltaTo(p2, offset_t);
    vlong_t const *z2 = DeltaTo(p2, offset_z);

    vlong_t *x3 = DeltaTo(out, offset_x);
    vlong_t *y3 = DeltaTo(out, offset_y);
    vlong_t *t3 = DeltaTo(out, offset_t);
    vlong_t *z3 = DeltaTo(out, offset_z);
    vlong_t *r = DeltaTo(opctx, offset_r);
    vlong_t *s = DeltaTo(opctx, offset_s);
    vlong_t *u = DeltaTo(opctx, offset_u);
    vlong_t *v = DeltaTo(opctx, offset_v);
    vlong_t *w = DeltaTo(opctx, offset_w);

    // r = x1 * y2
    // s = x2 * y1
    // w = r + s

    vlong_mulv_masked(r, x1, y2, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, x2, y1, 1, aux->modfunc, aux->mod_ctx);

    vlong_addv(w, r, s);
    aux->modfunc(w, aux->mod_ctx);

    // r = x1 * x2
    // s = y1 * y2
    // u = s - a * r

    vlong_mulv_masked(r, x1, x2, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, y1, y2, 1, aux->modfunc, aux->mod_ctx);

    vlong_imuls(u, r, curve->a, false);
    vlong_subv(u, s, u);
    ecp_imod_inplace(u, aux);

    // r = z1 * z2
    // s = t1 * t2
    // v = r * d_under - d_over * s

    vlong_mulv_masked(r, z1, z2, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, t1, t2, 1, aux->modfunc, aux->mod_ctx);

    vlong_muls(v, r, curve->d_under, false);
    vlong_imuls(v, s, -curve->d_over, true);
    ecp_imod_inplace(v, aux);

    // x3 = w * v
    // t3 = u & w

    vlong_mulv_masked(x3, w, v, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(t3, u, w, 1, aux->modfunc, aux->mod_ctx);

    // overwriting:
    // w = r * d_under + d_over * s

    vlong_muls(w, r, curve->d_under, false);
    vlong_imuls(w, s, curve->d_over, true);
    ecp_imod_inplace(w, aux);

    // y3 = u * w
    // z3 = v * w

    vlong_mulv_masked(y3, u, w, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(z3, v, w, 1, aux->modfunc, aux->mod_ctx);

    // x3 *= d_under
    // y3 *= d_under
    // t3 *= d_under ** 2

    vlong_muls(x3, x3, curve->d_under, false);
    vlong_muls(y3, y3, curve->d_under, false);
    vlong_muls(t3, t3, curve->d_under, false);
    aux->modfunc(x3, aux->mod_ctx);
    aux->modfunc(y3, aux->mod_ctx);
    aux->modfunc(t3, aux->mod_ctx);

    vlong_muls(t3, t3, curve->d_under, false);
    aux->modfunc(t3, aux->mod_ctx);

    return out;
}

ecEd_xytz_t *ecEd_point_dbl(
    ecEd_xytz_t *out, // intentionally not restrict-qualified,
    ecEd_xytz_t const *p1,
    ecEd_opctx_t *restrict opctx,
    ecEd_curve_t const *restrict curve)
{
    ecp_imod_aux_t const *aux = curve->imod_aux;

    vlong_t const *x1 = DeltaTo(p1, offset_x);
    vlong_t const *y1 = DeltaTo(p1, offset_y);
    // vlong_t const *t1 = DeltaTo(p1, offset_t); // unused, actually.
    vlong_t const *z1 = DeltaTo(p1, offset_z);

    vlong_t *x3 = DeltaTo(out, offset_x);
    vlong_t *y3 = DeltaTo(out, offset_y);
    vlong_t *t3 = DeltaTo(out, offset_t);
    vlong_t *z3 = DeltaTo(out, offset_z);

    vlong_t *r = DeltaTo(opctx, offset_r);
    vlong_t *s = DeltaTo(opctx, offset_s);
    vlong_t *u = DeltaTo(opctx, offset_u);
    vlong_t *v = DeltaTo(opctx, offset_v);
    vlong_t *w = DeltaTo(opctx, offset_w);

    // r = x1 * x1 * a
    // s = y1 * y1

    vlong_mulv_masked(r, x1, x1, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, y1, y1, 1, aux->modfunc, aux->mod_ctx);

    vlong_imuls(r, r, curve->a, false);
    ecp_imod_inplace(r, aux);

    // u = s + r
    // v = s - r

    vlong_addv(u, s, r);
    vlong_subv(v, s, r);

    aux->modfunc(u, aux->mod_ctx);
    ecp_imod_inplace(v, aux);

    // y3 = u * v

    vlong_mulv_masked(y3, u, v, 1, aux->modfunc, aux->mod_ctx);

    // s = x1 * y1 * 2

    vlong_mulv_masked(s, x1, y1, 1, aux->modfunc, aux->mod_ctx);
    vlong_addv(s, s, s);
    aux->modfunc(s, aux->mod_ctx);

    // t3 = s * v

    vlong_mulv_masked(t3, s, v, 1, aux->modfunc, aux->mod_ctx);

    // r = z1 * z1 * 2
    // w = r - u

    vlong_mulv_masked(r, z1, z1, 1, aux->modfunc, aux->mod_ctx);
    vlong_addv(r, r, r);
    vlong_subv(w, r, u);
    ecp_imod_inplace(w, aux);

    // x3 = s * w
    // z3 = u * w

    vlong_mulv_masked(x3, s, w, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(z3, u, w, 1, aux->modfunc, aux->mod_ctx);

    return out;
}

void ecEd_xytz_copy(
    ecEd_xytz_t *restrict dst,
    ecEd_xytz_t const *restrict src)
{
    vlong_cpy(DeltaTo(dst, offset_x), DeltaTo(src, offset_x));
    vlong_cpy(DeltaTo(dst, offset_y), DeltaTo(src, offset_y));
    vlong_cpy(DeltaTo(dst, offset_t), DeltaTo(src, offset_t));
    vlong_cpy(DeltaTo(dst, offset_z), DeltaTo(src, offset_z));
}

void ecEd_xytz_inf(ecEd_xytz_t *p)
{
    vlong_t *t;
    vlong_size_t i;

    t = DeltaTo(p, offset_x);
    for(i=0; i<t->c; i++) t->v[i] = 0;

    t = DeltaTo(p, offset_t);
    for(i=0; i<t->c; i++) t->v[i] = 0;

    t = DeltaTo(p, offset_y);
    t->v[0] = 1;
    for(i=1; i<t->c; i++) t->v[i] = 0;

    t = DeltaTo(p, offset_z);
    t->v[0] = 1;
    for(i=1; i<t->c; i++) t->v[i] = 0;
}

static void ecEd_xytz_substitute(
    ecEd_xytz_t *restrict a,
    ecEd_xytz_t const *restrict b,
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

    v1 = DeltaTo(a, offset_t);
    v2 = DeltaTo(b, offset_t);
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

ecEd_xytz_t *ecEd_point_scale_accumulate(
    ecEd_xytz_t *restrict accum,
    ecEd_xytz_t *restrict tmp1, // temporary variables are
    ecEd_xytz_t *restrict tmp2, // allocated by the caller
    ecEd_xytz_t const *restrict base,
    vlong_t const *restrict scalar,
    ecEd_opctx_t *restrict opctx,
    ecEd_curve_t const *restrict curve)
{
    ecEd_xytz_t *t;
    vlong_size_t f, i;
    uint32_t mask;

    ecEd_xytz_copy(tmp1, base);

    // 2022-05-02:
    // see note dated 2022-02-06 in ``ecp_point_scale_accumulate''
    // in "ecp-xyz.c"
    //- ecEd_xytz_inf(accum);

    f = scalar->c * 32;

    for(i=0;;)
    {
        mask = scalar->v[i / 32] >> (i % 32);
        mask &= 1;

        ecEd_point_add(tmp2, tmp1, accum, opctx, curve);
        ecEd_xytz_substitute(accum, tmp2, mask);

        if( ++i >= f ) break;

        ecEd_point_dbl(tmp2, tmp1, opctx, curve);
        t = tmp2, tmp2 = tmp1, tmp1 = t;

        continue;
    }

    return accum;
}

void ecEd_xytz_init(ecEd_xytz_t *xytz, unsigned bits)
{
    *xytz = ECED_XYTZ_HDR_INIT(bits);

    ((vlong_t *)DeltaTo(xytz, offset_x))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(xytz, offset_y))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(xytz, offset_t))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(xytz, offset_z))->c = VLONG_BITS_WCNT(bits);
}

void ecEd_opctx_init(ecEd_opctx_t *opctx, unsigned bits)
{
    *opctx = ECED_OPCTX_HDR_INIT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_r))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_s))->c = VLONG_BITS_WCNT(bits);

    ((vlong_t *)DeltaTo(opctx, offset_u))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_v))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_w))->c = VLONG_BITS_WCNT(bits);
}
