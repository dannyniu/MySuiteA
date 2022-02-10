/* DannyNiu/NJF. 2022-02-09. Public Domain. */

#include "ecdsa.h"
#include "../1-integers/vlong-dat.h"

void *ECDSA_Sign(
    ECSA_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng)
{
    unsigned slen = x->curve->plen < x->hlen ? x->curve->plen : x->hlen;
    uint8_t H[64] = {0}; // assumes no hash function has >512-bit output.
    
    void *restrict hashctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hx = &x->hfuncs;

    vlong_t *vl;
    vlong_size_t t;
    uint32_t w;
    
    ecp_opctx_t *opctx = DeltaTo(x, offset_opctx);
    ecp_xyz_t
        *Tmp1 = DeltaTo(x, offset_Tmp1),
        *Tmp2 = DeltaTo(x, offset_Tmp2);

    ecp_xyz_t *R = DeltaTo(x, offset_R);
    vlong_t *k = DeltaTo(x, offset_k);

    // generate ephemeral keypair:

start:
    ecp_xyz_inf(R);
    vl = DeltaTo(R, offset_x);
    while( true )
    {
        prng_gen(prng, H, slen);
        vlong_OS2IP(k, H, slen);
        ecp_point_scale_accumulate(
            R, Tmp1, Tmp2, x->curve->G,
            k, opctx, x->curve);
        
        for(t=0,w=0; t<vl->c; t++)
            w |= vl->v[t];
        if( w ) break;
    }

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
        (vlong_modfunc_t)vlong_remv_inplace,
        x->curve->n);

    // pt.2. e + r * d

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
    if( w ) return x;

    goto start;
}
