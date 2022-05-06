/* DannyNiu/NJF, 2022-05-05. Public Domain. */

#include "eddsa-misc.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

static_assert(
    ' ' == 0x20 && '0' == 0x30 && 'A' == 0x41,
    "ASCII character set is assumed. If not, adapt code for your charset");

#define Cond_p25519                             \
    pbits == 255 &&                             \
        curve->d_over == -121665 &&             \
        curve->d_under == 121666

#define Cond_p448                             \
    pbits == 448 &&                             \
        curve->d_over == -39081 &&             \
        curve->d_under == 1

void eddsa_ctxinit_basic(
    EdDSA_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param)
{
    ecEd_curve_t const *curve = (void const *)param[0].info(ecEd_PtrCurveDef);
    unsigned pbits = curve->pbits;
    void *hashctx;

    *x = EDDSA_CTX_INIT(
        param[0].info,
        param[1].info);
    
    ((vlong_t *)DeltaTo(x, offset_s))->c = VLONG_BITS_WCNT(pbits);
    ((vlong_t *)DeltaTo(x, offset_r))->c = VLONG_BITS_WCNT(pbits);

    ecEd_xytz_init(DeltaTo(x, offset_A), pbits);
    ecEd_xytz_init(DeltaTo(x, offset_R), pbits);
    ecEd_xytz_init(DeltaTo(x, offset_Tmp1), pbits);
    ecEd_xytz_init(DeltaTo(x, offset_Tmp2), pbits);
    ecEd_opctx_init(DeltaTo(x, offset_opctx), pbits);

    x->status = 0;
    x->flags = 0;

    x->hfuncs = HASH_FUNCS_SET_INIT(param[1].info);
    x->hashctx_size = param[1].info(contextBytes);
    hashctx = DeltaTo(x, offset_hashctx_init);
    x->hfuncs.initfunc(hashctx);
    
    if( Cond_p25519 )
    {
        // dom2(x,y) is by default empty.
    }
    else if( Cond_p448 )
    {
        x->hfuncs.updatefunc(hashctx, "SigEd448\0\0", 10);
    }
}

void eddsa_privkey_reload(EdDSA_Ctx_Hdr_t *x)
{
    uint8_t buf[128];
    
    ecEd_curve_t const *curve = x->curve;
    ecEd_opctx_t *opctx = DeltaTo(x, offset_opctx);
    
    unsigned pbits = curve->pbits;
    size_t plen = (pbits + 8) / 8;
    size_t t;
    
    void *hashctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hx = &x->hfuncs;

    hx->initfunc(hashctx);
    hx->updatefunc(hashctx, x->sk, plen);
    if( hx->xfinalfunc )
        hx->xfinalfunc(hashctx);
    hx->hfinalfunc(hashctx, buf, plen * 2);

    if( Cond_p25519 )
    {
        buf[0] &= 0xf8;
        buf[31] = 0x40 | (buf[31] & 0x7f);
    }
    else if( Cond_p448 )
    {
        buf[0] &= 0xfc;
        buf[55] |= 0x80;
        buf[56] = 0;
    }

    for(t=0; t<plen; t++)
        x->prefix[t] = buf[t + plen];

    vlong_DecLSB(DeltaTo(x, offset_s), buf, plen);
    ecEd_xytz_inf(DeltaTo(x, offset_A));
    
    ecEd_point_scale_accumulate(
        DeltaTo(x, offset_A),
        DeltaTo(x, offset_Tmp1),
        DeltaTo(x, offset_Tmp2),
        x->curve->B,
        DeltaTo(x, offset_s),
        opctx, x->curve);
    
    eddsa_canon_pubkey(x, DeltaTo(x, offset_A));
}

static vlong_t *ecEd_inv_mod_p_fermat(
    vlong_t *restrict out,
    vlong_t const *x,
    vlong_t *restrict tmp1,
    vlong_t *restrict tmp2,
    ecEd_curve_t const *restrict curve)
{
    return vlong_modexpv_shiftadded(
        out, x, tmp1, tmp2,
        curve->imod_aux->modfunc,
        curve->imod_aux->mod_ctx, -2, 0);
}

void eddsa_canon_pubkey(
    EdDSA_Ctx_Hdr_t *restrict x,
    ecEd_xytz_t *restrict Q)
{
    ecEd_opctx_t *opctx = DeltaTo(x, offset_opctx);
    
    ecEd_inv_mod_p_fermat(
        DeltaTo(opctx, offset_s),
        DeltaTo(Q,     offset_z),
        DeltaTo(opctx, offset_u),
        DeltaTo(opctx, offset_v),
        x->curve);
    
    vlong_mulv_masked(
        DeltaTo(opctx, offset_u),
        DeltaTo(Q,     offset_x),
        DeltaTo(opctx, offset_s), 1,
        (vlong_modfunc_t)
        x->curve->imod_aux->modfunc,
        x->curve->imod_aux->mod_ctx);

    vlong_mulv_masked(
        DeltaTo(opctx, offset_v),
        DeltaTo(Q,     offset_y),
        DeltaTo(opctx, offset_s), 1,
        (vlong_modfunc_t)
        x->curve->imod_aux->modfunc,
        x->curve->imod_aux->mod_ctx);

    vlong_mulv_masked(
        DeltaTo(opctx, offset_w),
        DeltaTo(Q,     offset_t),
        DeltaTo(opctx, offset_s), 1,
        (vlong_modfunc_t)
        x->curve->imod_aux->modfunc,
        x->curve->imod_aux->mod_ctx);

    vlong_cpy(DeltaTo(Q, offset_x), DeltaTo(opctx, offset_u));
    vlong_cpy(DeltaTo(Q, offset_y), DeltaTo(opctx, offset_v));
    vlong_cpy(DeltaTo(Q, offset_t), DeltaTo(opctx, offset_w));
    vlong_cpy(DeltaTo(Q, offset_z), vlong_one);
}

void eddsa_point_enc(
    EdDSA_Ctx_Hdr_t const *restrict x,
    uint8_t buf[restrict],
    ecEd_xytz_t const *restrict Q)
{
    size_t pbits = x->curve->pbits;
    size_t pbytes = (pbits + 7) / 8;
    size_t bitpos =  pbits % 8;
    int par;
    
    vlong_EncLSB(DeltaTo(Q, offset_y), buf, pbytes);
    buf[pbits / 8] &= (1 << bitpos) - 1;

    par = ((vlong_t const *)DeltaTo(Q, offset_x))->v[0] & 1;
    buf[pbits / 8] |= par << bitpos;
}

static VLONG_T(8) po2_25519 = {
    .c = 8,
    .v[7] = 0x2b832480, 
    .v[6] = 0x4fc1df0b, 
    .v[5] = 0x2b4d0099, 
    .v[4] = 0x3dfbd7a7, 
    .v[3] = 0x2f431806, 
    .v[2] = 0xad2fe478, 
    .v[1] = 0xc4ee1b27, 
    .v[0] = 0x4a0ea0b0,
};

static vlong_t *getx_p25519(
    EdDSA_Ctx_Hdr_t *restrict ctx,
    ecEd_xytz_t *restrict Q) // recovers Q.x from Q.y.
{
    ecEd_curve_t const *curve = ctx->curve;
    ecp_imod_aux_t const *aux = curve->imod_aux;
    ecEd_opctx_t *opctx = DeltaTo(ctx, offset_opctx);
    ecEd_xytz_t *tmp = DeltaTo(ctx, offset_Tmp1);
    
    vlong_t *r = DeltaTo(opctx, offset_r);
    vlong_t *s = DeltaTo(opctx, offset_s);
    vlong_t *u = DeltaTo(opctx, offset_u);
    vlong_t *v = DeltaTo(opctx, offset_v);
    vlong_t *w = DeltaTo(opctx, offset_w);

    vlong_t *a = DeltaTo(tmp, offset_x);
    // vlong_t *b = DeltaTo(tmp, offset_y);
    vlong_t *c = DeltaTo(tmp, offset_t);
    vlong_t *d = DeltaTo(tmp, offset_z);
    
    vlong_t *x = DeltaTo(Q, offset_x);
    vlong_t *y = DeltaTo(Q, offset_y);

    // v = u := y**2
    vlong_mulv_masked(u, y, y, 1, aux->modfunc, aux->mod_ctx);
    vlong_cpy(v, u);

    // u = (y**2 - 1) * d_under
    vlong_adds(u, u, -1, 0);
    vlong_imuls(u, u, curve->d_under, false);

    // v = d_over * y**2 + d_under
    vlong_imuls(v, v, curve->d_over, false);
    vlong_adds(v, v, curve->d_under, 0);

    ecp_imod_inplace(u, aux);
    ecp_imod_inplace(v, aux);

    // a := v ** 3
    // r = u * v**7
    vlong_mulv_masked(r, v, v, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, r, v, 1, aux->modfunc, aux->mod_ctx);
    vlong_cpy(a, s); // v ** 3.
    
    vlong_mulv_masked(r, s, s, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, r, v, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(r, s, u, 1, aux->modfunc, aux->mod_ctx);

    // s := {r} ** ((p - 5) / 8) == (u v**7)**((p - 5) / 8) mod p
    vlong_modexpv_shiftadded(
        s, r, c, d,
        aux->modfunc,
        aux->mod_ctx,
        -5, 3);

    // x = {s} * u * v**3
    vlong_mulv_masked(r, s, a, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(x, r, u, 1, aux->modfunc, aux->mod_ctx);

    // verify.
    vlong_mulv_masked(w, x, x, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(r, v, w, 1, aux->modfunc, aux->mod_ctx);
    if( vlong_cmpv_shifted(r, u, 0) == 0 )
        return x;

    vlong_subv(r, curve->p, r);
    if( vlong_cmpv_shifted(r, u, 0) == 0 )
    {
        vlong_mulv_masked(
            r, x, (vlong_t *)&po2_25519,
            1, aux->modfunc, aux->mod_ctx);
        vlong_cpy(x, r);
        return x;
    }

    return NULL;
}

static vlong_t *getx_p448(
    EdDSA_Ctx_Hdr_t *restrict ctx,
    ecEd_xytz_t *restrict Q) // recovers Q.x from Q.y.
{
    ecEd_curve_t const *curve = ctx->curve;
    ecp_imod_aux_t const *aux = curve->imod_aux;
    ecEd_opctx_t *opctx = DeltaTo(ctx, offset_opctx);
    ecEd_xytz_t *tmp = DeltaTo(ctx, offset_Tmp1);
    
    vlong_t *r = DeltaTo(opctx, offset_r);
    vlong_t *s = DeltaTo(opctx, offset_s);
    vlong_t *u = DeltaTo(opctx, offset_u);
    vlong_t *v = DeltaTo(opctx, offset_v);
    vlong_t *w = DeltaTo(opctx, offset_w);

    vlong_t *a = DeltaTo(tmp, offset_x);
    // vlong_t *b = DeltaTo(tmp, offset_y);
    vlong_t *c = DeltaTo(tmp, offset_t);
    vlong_t *d = DeltaTo(tmp, offset_z);
    
    vlong_t *x = DeltaTo(Q, offset_x);
    vlong_t *y = DeltaTo(Q, offset_y);

    // v = u := y**2
    vlong_mulv_masked(u, y, y, 1, aux->modfunc, aux->mod_ctx);
    vlong_cpy(v, u);

    // u = (y**2 - 1) * d_under
    vlong_adds(u, u, -1, 0);
    vlong_imuls(u, u, curve->d_under, false);

    // v = d_over * y**2 - d_under
    vlong_imuls(v, v, curve->d_over, false);
    vlong_adds(v, v, -curve->d_under, 0);

    ecp_imod_inplace(u, aux);
    ecp_imod_inplace(v, aux);

    // s := v**3
    vlong_mulv_masked(r, v, v, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, r, v, 1, aux->modfunc, aux->mod_ctx);

    // a := u**2
    // w := u**5
    vlong_mulv_masked(a, u, u, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(r, a, a, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(w, r, u, 1, aux->modfunc, aux->mod_ctx);

    // r = {w} * {s} = u**5 * v**3
    vlong_mulv_masked(r, w, s, 1, aux->modfunc, aux->mod_ctx);

    // s := {r} ** ((p - 3) / 4) mod p
    vlong_modexpv_shiftadded(
        s, r, c, d,
        aux->modfunc,
        aux->mod_ctx,
        -3, 2);

    // x = {s} * u**3 * v
    vlong_mulv_masked(r, s, a, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(s, r, u, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(x, s, v, 1, aux->modfunc, aux->mod_ctx);

    // verify.
    vlong_mulv_masked(w, x, x, 1, aux->modfunc, aux->mod_ctx);
    vlong_mulv_masked(r, v, w, 1, aux->modfunc, aux->mod_ctx);
    if( vlong_cmpv_shifted(r, u, 0) == 0 )
        return x;

    return NULL;
}

void *eddsa_point_dec(
    EdDSA_Ctx_Hdr_t *restrict ctx,
    uint8_t const buf[restrict],
    ecEd_xytz_t *restrict Q)
{
    ecEd_curve_t const *curve = ctx->curve;
    ecp_imod_aux_t const *aux = curve->imod_aux;
    size_t pbits = curve->pbits;
    size_t pbytes = (pbits + 7) / 8;
    size_t bitpos =  pbits % 8;
    int par;

    vlong_t *x;
    vlong_t *y = DeltaTo(Q, offset_y);
    vlong_t *t = DeltaTo(Q, offset_t);
    vlong_t *z = DeltaTo(Q, offset_z);
    vlong_size_t i;
    uint32_t w;

    par = (buf[pbits / 8] >> bitpos) & 1;

    vlong_DecLSB(y, buf, pbytes);
    y->v[pbits / 32] &= (1 << (pbits % 32)) - 1;

    if( Cond_p25519 )
    {
        x = getx_p25519(ctx, Q);
    }
    else if( Cond_p448 )
    {
        x = getx_p448(ctx, Q);
    }
    else return NULL; // unknown curve, not implemented.

    if( !x ) return NULL;

    for(w=0,i=0; i<x->c; i++) w |= x->v[i];
    if( w == 0 && par == 1 ) return NULL;

    if( (1 & x->v[0]) ^ par ) vlong_subv(x, curve->p, x);

    vlong_mulv_masked(t, x, y, 1, aux->modfunc, aux->mod_ctx);
    vlong_cpy(z, vlong_one);
    return Q;
}
