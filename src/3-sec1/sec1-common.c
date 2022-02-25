/* DannyNiu/NJF, 2022-02-11. Public Domain. */

#include "sec1-common.h"
#include "../2-ec/ecp-pubkey-codec.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

void topword_modmask(uint32_t *x, uint32_t const *m)
{
    uint32_t w = *m;
    w |= w >> 16;
    w |= w >> 8;
    w |= w >> 4;
    w |= w >> 2;
    w |= w >> 1;
    *x &= w;
}

static void sec1_canon_pubkey(SEC1_Base_Ctx_Hdr_t *restrict x)
{
    ecp_opctx_t *opctx = DeltaTo(x, offset_opctx);
    ecp_xyz_t *Q = DeltaTo(x, offset_Q);

    // canonicalize.
    
    vlong_inv_mod_p_fermat(
        DeltaTo(opctx, offset_w),
        DeltaTo(Q,     offset_z),
        DeltaTo(opctx, offset_u),
        DeltaTo(opctx, offset_v),
        x->curve);

    vlong_mulv_masked(
        DeltaTo(opctx, offset_u),
        DeltaTo(Q,     offset_x),
        DeltaTo(opctx, offset_w), 1,
        (vlong_modfunc_t)
        x->curve->imod_aux->modfunc,
        x->curve->imod_aux->mod_ctx);

    vlong_mulv_masked(
        DeltaTo(opctx, offset_v),
        DeltaTo(Q,     offset_y),
        DeltaTo(opctx, offset_w), 1,
        (vlong_modfunc_t)
        x->curve->imod_aux->modfunc,
        x->curve->imod_aux->mod_ctx);

    vlong_cpy(DeltaTo(Q, offset_x), DeltaTo(opctx, offset_u));
    vlong_cpy(DeltaTo(Q, offset_y), DeltaTo(opctx, offset_v));
    vlong_cpy(DeltaTo(Q, offset_z), vlong_one);
}

static void sec1_ctxinit_basic(
    SEC1_Base_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param)
{
    const ecp_curve_t *curve = (const void *)param[0].info(ptrCurveDef);
    unsigned bits = curve->plen * 8;
        
    *x = SEC1_CTX_INIT(
        SEC1_Base_Ctx_Hdr_t,
        param[0].info,
        param[1].info);

    ((vlong_t *)DeltaTo(x, offset_d))->c = VLONG_BYTES_WCNT(curve->plen);
    ((vlong_t *)DeltaTo(x, offset_k))->c = VLONG_BYTES_WCNT(curve->plen);

    ecp_xyz_init(DeltaTo(x, offset_R), bits);
    ecp_xyz_init(DeltaTo(x, offset_Q), bits);
    ecp_xyz_init(DeltaTo(x, offset_Tmp1), bits);
    ecp_xyz_init(DeltaTo(x, offset_Tmp2), bits);
    ecp_opctx_init(DeltaTo(x, offset_opctx), bits);
}

static void sec1_gen_privkey(
    SEC1_Base_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen, void *restrict prng)
{
    uint8_t H[128];

    ecp_opctx_t *opctx = DeltaTo(x, offset_opctx);
    ecp_xyz_t
        *Tmp1 = DeltaTo(x, offset_Tmp1),
        *Tmp2 = DeltaTo(x, offset_Tmp2);

    ecp_xyz_t *Q = DeltaTo(x, offset_Q);
    vlong_t *d = DeltaTo(x, offset_d);

    do
    {
        prng_gen(prng, H, x->curve->plen);
        vlong_OS2IP(d, H, x->curve->plen);
        topword_modmask(
            (x->curve->plen - 1) / 4 + d->v,
            (x->curve->plen - 1) / 4 + x->curve->p->v);

        if( vlong_cmpv_shifted(d, x->curve->n, 0) != 2 )
            continue;
        
        if( vlong_cmpv_shifted(vlong_one, d, 0) == 1 )
            continue;

        ecp_xyz_inf(Q);
        ecp_point_scale_accumulate(
            Q, Tmp1, Tmp2, x->curve->G,
            d, opctx, x->curve);
        break;
    }
    while( true );

    sec1_canon_pubkey(x);
}

static void *sec1_dec_privkey(
    SEC1_Base_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen)
{
    // ``enclen'' shall equal ``x->curve->plen''.
    // ``d'' shall be within [1,n)
    // if consistent, ``x'' is returned, otherwise NULL.

    ecp_opctx_t *opctx = DeltaTo(x, offset_opctx);
    ecp_xyz_t
        *Tmp1 = DeltaTo(x, offset_Tmp1),
        *Tmp2 = DeltaTo(x, offset_Tmp2);

    ecp_xyz_t *Q = DeltaTo(x, offset_Q);
    vlong_t *d = DeltaTo(x, offset_d);

    if( enclen != x->curve->plen )
        return NULL;
    
    vlong_OS2IP(d, enc, enclen);

    if( vlong_cmpv_shifted(d, x->curve->n, 0) != 2 )
        return NULL;
        
    if( vlong_cmpv_shifted(vlong_one, d, 0) == 1 )
        return NULL;

    ecp_xyz_inf(Q);
    ecp_point_scale_accumulate(
        Q, Tmp1, Tmp2, x->curve->G,
        d, opctx, x->curve);

    sec1_canon_pubkey(x);

    return x;
}

IntPtr SEC1_Keygen(
    SEC1_Base_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    if( !x ) return SEC1_CTX_SIZE(param[0].info, param[1].info); else
    {
        sec1_ctxinit_basic(x, param);        
        sec1_gen_privkey((void *)x, prng_gen, prng);
        return (IntPtr)x;
    }
}

IntPtr SEC1_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    SEC1_Base_Ctx_Hdr_t const *x = any;
    param = NULL;
    
    if( enc )
    {
        if( enclen != x->curve->plen ) return -1;
        vlong_I2OSP(DeltaTo(x, offset_d), enc, x->curve->plen);
    }
    return x->curve->plen;
}

IntPtr SEC1_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    SEC1_Base_Ctx_Hdr_t *x = any;

    if( any )
    {
        sec1_ctxinit_basic(x, param);

        if( !sec1_dec_privkey(any, enc, enclen) )
            return -1;
    }
    return SEC1_CTX_SIZE(param[0].info, param[1].info);
}

IntPtr SEC1_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    SEC1_Base_Ctx_Hdr_t const *x = any;
    param = NULL;
    
    if( enc )
    {
        if( ecp_point_encode(
                DeltaTo(x, offset_Q),
                enc, enclen, x->curve) )
            return (IntPtr)enclen;

        else return -1;
    }
    else return 1 + x->curve->plen * 2;
}

IntPtr SEC1_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    SEC1_Base_Ctx_Hdr_t *x = any;
    const ecp_curve_t *curve = (const void *)param[0].info(ptrCurveDef);

    if( any )
    {
        sec1_ctxinit_basic(x, param);

        if( !ecp_point_decode(
                DeltaTo(x, offset_Q),
                enc, enclen,
                DeltaTo(x, offset_R),
                DeltaTo(x, offset_Tmp1),
                DeltaTo(x, offset_Tmp2),
                DeltaTo(x, offset_opctx),
                curve) )
            return -1;
    }
    return SEC1_CTX_SIZE(param[0].info, param[1].info);
}
