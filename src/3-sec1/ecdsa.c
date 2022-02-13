/* DannyNiu/NJF. 2022-02-09. Public Domain. */

#include "ecdsa.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

IntPtr ECDSA_Keygen(
    ECDSA_Priv_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    const ecp_curve_t *curve = (const void *)param[0].info(ptrCurveDef);

    if( x )
    {
        unsigned bits = curve->plen * 8;
        
        *x = ECDSA_PRIV_CTX_INIT(
            param[0].info,
            param[1].info);

        ((vlong_t *)DeltaTo(x, offset_d))->c = VLONG_BYTES_WCNT(curve->plen);
        ((vlong_t *)DeltaTo(x, offset_k))->c = VLONG_BYTES_WCNT(curve->plen);

        ecp_xyz_init(DeltaTo(x, offset_R), bits);
        ecp_xyz_init(DeltaTo(x, offset_Q), bits);
        ecp_xyz_init(DeltaTo(x, offset_Tmp1), bits);
        ecp_xyz_init(DeltaTo(x, offset_Tmp2), bits);
        ecp_opctx_init(DeltaTo(x, offset_opctx), bits);

        SEC1_Keygen((SEC1_Common_Priv_Ctx_Hdr_t *)x, prng_gen, prng);
        return (IntPtr)x;
    }
    
    else
    {
        return ECDSA_PRIV_CTX_SIZE(param[0].info, param[1].info);
    }
}

void *ECDSA_Sign(
    ECDSA_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng)
{
    unsigned slen = x->curve->plen < x->hlen ? x->curve->plen : x->hlen;
    uint8_t H[64] = {0}; // assumes no hash function has >512-bit output.
    
    void *restrict hashctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hx = &x->hfuncs;

    vlong_size_t t;
    vlong_t *vl;
    uint32_t w;
    
    ecp_opctx_t *opctx = DeltaTo(x, offset_opctx);
    ecp_xyz_t
        *Tmp1 = DeltaTo(x, offset_Tmp1),
        *Tmp2 = DeltaTo(x, offset_Tmp2);

    ecp_xyz_t *R = DeltaTo(x, offset_R);
    vlong_t *k = DeltaTo(x, offset_k);
    static const VLONG_T(1) one = { .c = 1, .v[0] = 1, };

    // generate ephemeral keypair:

start:
    vl = DeltaTo(R, offset_x);

    do
    {
        prng_gen(prng, H, slen);
        vlong_OS2IP(k, H, slen);

        if( vlong_cmpv_shifted(k, x->curve->n, 0) != 2 )
            continue;
        
        if( vlong_cmpv_shifted((const vlong_t *)&one, k, 0) == 1 )
            continue;
        
        ecp_xyz_inf(R);
        ecp_point_scale_accumulate(
            R, Tmp1, Tmp2, x->curve->G,
            k, opctx, x->curve);
        
        for(t=0,w=0; t<vl->c; t++)
            w |= vl->v[t];
        if( w ) break;
    }
    while( true );


    // hash the message.

    hx->initfunc(hashctx);
    hx->updatefunc(hashctx, msg, msglen);
    
    if( hx->xfinalfunc )
        hx->xfinalfunc(hashctx);
    
    hx->hfinalfunc(hashctx, H, slen);

    // compute s = k^{-1} * (e + r * d) mod n

    // pt.1. r = r.X / r.Z
    
    vlong_inv_mod_p_fermat(
        DeltaTo(opctx, offset_w),
        DeltaTo(R, offset_z),
        DeltaTo(opctx, offset_u),
        DeltaTo(opctx, offset_v),
        x->curve);

    vlong_mulv_masked(
        DeltaTo(opctx, offset_r),
        DeltaTo(opctx, offset_w),
        vl, 1,
        x->curve->imod_aux->modfunc,
        x->curve->imod_aux->mod_ctx);

    // pt.2. {w} = e + r * d

    vlong_mulv_masked(
        DeltaTo(opctx, offset_u), // u == r * d
        DeltaTo(opctx, offset_r),
        DeltaTo(x, offset_d), 1,
        (vlong_modfunc_t)vlong_remv_inplace,
        x->curve->n);

    vlong_OS2IP(
        DeltaTo(opctx, offset_v), // v == e
        H, slen);

    vlong_addv(
        DeltaTo(opctx, offset_w), // w == u + v == e + r * d
        DeltaTo(opctx, offset_u),
        DeltaTo(opctx, offset_v));

    vlong_remv_inplace(
        DeltaTo(opctx, offset_w),
        x->curve->n);

    // pt.3. s = (w) * k^{-1}

    vlong_inv_mod_n_fermat(
        DeltaTo(opctx, offset_t), k,
        DeltaTo(opctx, offset_u),
        DeltaTo(opctx, offset_v),
        x->curve);

    vlong_mulv_masked(
        DeltaTo(opctx, offset_s),
        DeltaTo(opctx, offset_t),
        DeltaTo(opctx, offset_w), 1,
        (vlong_modfunc_t)vlong_remv_inplace,
        x->curve->n);

    // check s != 0.
    
    vl = DeltaTo(opctx, offset_s);
    for(t=0,w=0; t<vl->c; t++)
        w |= vl->v[t];
    if( w )
    {
        x->status = 1;
        return x;
    }

    goto start;
}
