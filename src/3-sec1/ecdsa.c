/* DannyNiu/NJF. 2022-02-09. Public Domain. */

#include "ecdsa.h"
#include "../2-ec/ecp-pubkey-codec.h"
#include "../0-exec/struct-delta.c.h"

#if ! PKC_OMIT_PRIV_OPS

#if ! PKC_OMIT_KEYGEN

IntPtr ECDSA_Keygen(
    ECDSA_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    IntPtr ret = ECC_Keygen((ECC_Base_Ctx_Hdr_t *)x, param, prng_gen, prng);

    if( x )
    {
        x->hlen = param[1].info(outBytes);
        x->hfuncs = HASH_FUNCS_SET_INIT(param[1].info);
        x->context_type = 2;
        x->offset_hashctx = sizeof(ECDSA_Ctx_Hdr_t);
    }

    return ret;
}

#endif /* ! PKC_OMIT_KEYGEN */

IntPtr ECDSA_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    return ECC_Encode_PrivateKey(any, enc, enclen, param);
}

IntPtr ECDSA_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    IntPtr ret = ECC_Decode_PrivateKey(any, enc, enclen, param);

    if( any )
    {
        ECDSA_Ctx_Hdr_t *x = any;

        x->hlen = param[1].info(outBytes);
        x->hfuncs = HASH_FUNCS_SET_INIT(param[1].info);
        x->context_type = 2;
        x->offset_hashctx = sizeof(ECDSA_Ctx_Hdr_t);
    }

    return ret;
}

IntPtr ECDSA_Export_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    return ECC_Encode_PublicKey(any, enc, enclen, param);
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

IntPtr ECDSA_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    return ECC_Encode_PublicKey(any, enc, enclen, param);
}

IntPtr ECDSA_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    IntPtr ret = ECC_Decode_PublicKey(any, enc, enclen, param);

    if( any )
    {
        ECDSA_Ctx_Hdr_t *x = any;

        x->hlen = param[1].info(outBytes);
        x->hfuncs = HASH_FUNCS_SET_INIT(param[1].info);
        x->context_type = 2;
        x->offset_hashctx = sizeof(ECDSA_Ctx_Hdr_t);
    }

    return ret;
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! PKC_OMIT_PRIV_OPS

void *ECDSA_Sign(
    ECDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng)
{
    unsigned slen = x->curve->plen < x->hlen ? x->curve->plen : x->hlen;
    uint8_t H[128] = {0}; // increased per [crypto.SE]/q/98794.

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

    // generate ephemeral keypair:

start:
    vl = DeltaTo(R, offset_x);

    do
    {
        prng_gen(prng, H, x->curve->plen);
        vlong_OS2IP(k, H, x->curve->plen);
        topword_modmask(
            (x->curve->plen - 1) / 4 + k->v,
            (x->curve->plen - 1) / 4 + x->curve->p->v);

        if( vlong_cmpv_shifted(k, x->curve->n, 0) != 2 )
            continue;

        if( vlong_cmpv_shifted(vlong_one, k, 0) == 1 )
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

    if( x->status != 2 )
    {
        x->status = 2;
        hx->initfunc(hashctx);
        hx->updatefunc(hashctx, msg, msglen);
    }

    if( hx->xfinalfunc )
        hx->xfinalfunc(hashctx);

    hx->hfinalfunc(hashctx, H, slen);

    // compute s = k^{-1} * (e + r * d) mod n

    // pt.1. r = r.X / r.Z

    vlong_inv_mod_p_fermat(
        DeltaTo(opctx, offset_w),
        DeltaTo(R,     offset_z),
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
        DeltaTo(x,     offset_d), 1,
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

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

void const *ECDSA_Verify(
    ECDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen)
{
    unsigned slen = x->curve->plen < x->hlen ? x->curve->plen : x->hlen;
    uint8_t H[128] = {0}; // increased per [crypto.SE]/q/98794.

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

    if( x->status == 1 ) return msg;
    if( x->status == -1 ) return NULL;

    // range check for r and s.

    if( vlong_cmpv_shifted(DeltaTo(opctx, offset_r), x->curve->n, 0) != 2 )
        goto reject;

    if( vlong_cmpv_shifted(DeltaTo(opctx, offset_s), x->curve->n, 0) != 2 )
        goto reject;

    if( vlong_cmpv_shifted(vlong_one, DeltaTo(opctx, offset_r), 0) == 1 )
        goto reject;

    if( vlong_cmpv_shifted(vlong_one, DeltaTo(opctx, offset_s), 0) == 1 )
        goto reject;

    // hash the message.

    hx->initfunc(hashctx);
    hx->updatefunc(hashctx, msg, msglen);

    if( hx->xfinalfunc )
        hx->xfinalfunc(hashctx);

    hx->hfinalfunc(hashctx, H, slen);

    // u1 = e * s^{-1} mod n , u2 = r * s^{-1} mod n .

    vlong_OS2IP(
        DeltaTo(opctx, offset_w), // {w} == e
        H, slen);

    vlong_I2OSP( // save signature component 'r' for a moment.
        DeltaTo(opctx, offset_r),
        H, x->curve->plen);

    vlong_inv_mod_n_fermat(
        DeltaTo(opctx, offset_t), // {t} == s^{-1}
        DeltaTo(opctx, offset_s),
        DeltaTo(opctx, offset_u),
        DeltaTo(opctx, offset_v),
        x->curve);

    vlong_mulv_masked(
        DeltaTo(x,     offset_d), // u1 = {d} = e * s^{-1} = {w} * {t}
        DeltaTo(opctx, offset_w),
        DeltaTo(opctx, offset_t), 1,
        (vlong_modfunc_t)vlong_remv_inplace,
        x->curve->n);

    vlong_mulv_masked(
        DeltaTo(x,     offset_k), // u2 = {k} = r * s^{-1} = r * {t}
        DeltaTo(opctx, offset_r),
        DeltaTo(opctx, offset_t), 1,
        (vlong_modfunc_t)vlong_remv_inplace,
        x->curve->n);

    // R = u1 * G + u2 * Q && R != O.

    ecp_xyz_inf(R);

    ecp_point_scale_accumulate(
        R, Tmp1, Tmp2, x->curve->G,
        DeltaTo(x, offset_d), // {d} == u1.
        opctx, x->curve);

    ecp_point_scale_accumulate(
        R, Tmp1, Tmp2, DeltaTo(x, offset_Q),
        DeltaTo(x, offset_k), // {k} == u2.
        opctx, x->curve);

    vl = DeltaTo(R, offset_z);

    for(t=0,w=0; t<vl->c; t++)
        w |= vl->v[t];
    if( !w ) goto reject;

    // x_R == r.

    vlong_inv_mod_p_fermat(
        DeltaTo(opctx, offset_w),
        DeltaTo(R,     offset_z),
        DeltaTo(opctx, offset_u),
        DeltaTo(opctx, offset_v),
        x->curve);

    vlong_mulv_masked(
        DeltaTo(opctx, offset_t),
        DeltaTo(opctx, offset_w),
        DeltaTo(R,     offset_x), 1,
        x->curve->imod_aux->modfunc,
        x->curve->imod_aux->mod_ctx);

    vlong_OS2IP( // restore signature component 'r'.
        DeltaTo(opctx, offset_r),
        H, x->curve->plen);

    if( vlong_cmpv_shifted(
            DeltaTo(opctx, offset_t),
            DeltaTo(opctx, offset_r),
            0) != 0 )
        goto reject;

    x->status = 1;
    return msg;

reject:
    x->status = -1;
    return NULL;
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! PKC_OMIT_PRIV_OPS

void *ECDSA_Encode_Signature(
    ECDSA_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen)
{
    IntPtr minlen = ber_tlv_ecc_encode_dss_signature(x, NULL, 0);

    if( !sig )
    {
        *siglen = minlen;
        return NULL;
    }

    if( *siglen < (size_t)minlen ) return NULL;

    ber_tlv_ecc_encode_dss_signature(x, sig, *siglen);
    return sig;
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

void *ECDSA_Decode_Signature(
    ECDSA_Ctx_Hdr_t *restrict x,
    void const *restrict sig, size_t siglen)
{
    int subret = ber_tlv_ecc_decode_dss_signature(x, sig, siglen);
    x->status = 0;

    if( subret == -1 ) return NULL;
    else return x;
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS)

IntPtr iECDSA_KeyCodec(int q) { return xECDSA_KeyCodec(q); }

IntPtr tECDSA(const CryptoParam_t *P, int q)
{
    return xECDSA(P[0].info, P[1].info, q);
}

IntPtr iECDSA_CtCodec(int q) { return xECDSA_CtCodec(q); }

#endif /* ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS) */
