/* DannyNiu/NJF, 2022-04-27. Public Domain. */

#include "ecMt.h"
#include "../0-exec/struct-delta.c.h"

#define vdecl(name) vlong_t *name = DeltaTo(opctx, offset_##name)

static void cswap(int swap, vlong_t *a, vlong_t *b)
{
    vlong_size_t t;
    uint32_t dummy;

    for(t=0; t<a->c || t<b->c; t++)
    {
        dummy = (uint32_t)-swap;
        dummy &= (t<a->c ? a->v[t] : 0) ^ (t<b->c ? b->v[t] : 0);
        if( t < a->c ) a->v[t] ^= dummy;
        if( t < b->c ) b->v[t] ^= dummy;
    }
}

vlong_t *ecMt_point_scale(
    vlong_t const *restrict k,
    vlong_t *restrict x1,
    uint32_t a24,
    vlong_size_t bits,
    ecMt_opctx_t *restrict opctx,
    ecp_imod_aux_t const *restrict imod_aux)
{
    // entirely based on rfc-7748.
    
    vdecl(x2);
    vdecl(z2);
    vdecl(x3);
    vdecl(z3);
    
    vdecl(da);
    vdecl(cb);
    vdecl(tmp);
    
    vdecl(a);
    vdecl(b);
    vdecl(c);
    vdecl(d);
    vdecl(e);

    int swap = 0;
    int kt;
    vlong_size_t t;

    imod_aux->modfunc(x1, imod_aux->mod_ctx);

    vlong_cpy(x2, vlong_one);
    vlong_cpy(z3, vlong_one);
    vlong_cpy(x3, x1);
    for(t=0; t<z2->c; t++) z2->v[t] = 0;

    for(t=bits; t--;)
    {
        // assumes uint32_t;
        static_assert(
            sizeof(*k->v) == sizeof(uint32_t),
            "Data type assumption failed");
        kt = k->v[t / 32] >> (t % 32);
        kt &= 1;
        
        swap ^= kt;
        cswap(swap, x2, x3);
        cswap(swap, z2, z3);
        swap = kt;

        // aa = {c} = (x2 + z2) ** 2
        // bb = {d} = (x2 - z2) ** 2
        vlong_addv(a, x2, z2);
        vlong_subv(b, x2, z2);
        imod_aux->modfunc(a, imod_aux->mod_ctx);
        ecp_imod_inplace(b, imod_aux);
        vlong_mulv_masked(c, a, a, 1, imod_aux->modfunc, imod_aux->mod_ctx);
        vlong_mulv_masked(d, b, b, 1, imod_aux->modfunc, imod_aux->mod_ctx);

        // x2 = aa * bb = {c} * {d}
        vlong_mulv_masked(x2, c, d, 1, imod_aux->modfunc, imod_aux->mod_ctx);

        // e = aa - bb = {c} - {d}
        vlong_subv(e, c, d);
        ecp_imod_inplace(e, imod_aux);

        // aa += a24 * e :: {c} += a24 * e
        vlong_muls(c, e, a24, true);
        imod_aux->modfunc(c, imod_aux->mod_ctx);

        // z2 = e * {c}
        vlong_mulv_masked(z2, e, c, 1, imod_aux->modfunc, imod_aux->mod_ctx);

        // c = x3 + z3
        // d = x3 - z3
        // da = d * a
        // cb = c * b
        vlong_addv(c, x3, z3);
        vlong_subv(d, x3, z3);
        imod_aux->modfunc(c, imod_aux->mod_ctx);
        ecp_imod_inplace(d, imod_aux);
        vlong_mulv_masked(da, d, a, 1, imod_aux->modfunc, imod_aux->mod_ctx);
        vlong_mulv_masked(cb, c, b, 1, imod_aux->modfunc, imod_aux->mod_ctx);

        // tmp = da + cb
        vlong_addv(tmp, da, cb);
        imod_aux->modfunc(tmp, imod_aux->mod_ctx);

        // x3 = tmp ** 2
        vlong_mulv_masked(x3, tmp, tmp, 1, imod_aux->modfunc, imod_aux->mod_ctx);

        // tmp = da - cb
        vlong_subv(tmp, da, cb);
        ecp_imod_inplace(tmp, imod_aux);

        // {e} = tmp ** 2
        vlong_mulv_masked(e, tmp, tmp, 1, imod_aux->modfunc, imod_aux->mod_ctx);

        // z3 = x1 * {e}
        vlong_mulv_masked(z3, x1, e, 1, imod_aux->modfunc, imod_aux->mod_ctx);
    }

    cswap(swap, x2, x3);
    cswap(swap, z2, z3);

    vlong_modexpv_shiftadded(
        tmp, z2, a, b,
        imod_aux->modfunc,
        imod_aux->mod_ctx, -2, 0);

    vlong_mulv_masked(x1, x2, tmp, 1, imod_aux->modfunc, imod_aux->mod_ctx);
    return x1;
}

void ecMt_opctx_init(ecMt_opctx_t *opctx, unsigned bits)
{
    *opctx = ECMT_OPCTX_HDR_INIT(bits);

    ((vlong_t *)DeltaTo(opctx, offset_x2))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_z2))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_x3))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_z3))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_da))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_cb))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_tmp))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_a))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_b))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_c))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_d))->c = VLONG_BITS_WCNT(bits);
    ((vlong_t *)DeltaTo(opctx, offset_e))->c = VLONG_BITS_WCNT(bits);
}
