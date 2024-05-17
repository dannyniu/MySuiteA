/* DannyNiu/NJF. 2022-02-09. Public Domain. */

#include "sm2sig.h"
#include "../2-ec/ecp-pubkey-codec.h"
#include "../2-ec/curveSM2.h"
#include "../2-hash/sm3.h"
#include "../0-exec/struct-delta.c.h"

#if ! PKC_OMIT_PRIV_OPS

#if ! PKC_OMIT_KEYGEN

static void sm2sig_setZ(
    SM2SIG_Ctx_Hdr_t *restrict x,
    const void *ID_A, uint16_t idlen)
{
    ecp_opctx_t *opctx = DeltaTo(x, offset_opctx);
    ecp_xyz_t *pubkey = DeltaTo(x, offset_Q);

    uint8_t buf[128];
    void *restrict hctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hfnx = &x->hfuncs;

    vlong_t *vl;
    vlong_size_t t;

    hfnx->initfunc(hctx);
    buf[0] = (idlen * 8) >> 8;
    buf[1] = (idlen * 8);
    hfnx->updatefunc(hctx, buf, 2);
    hfnx->updatefunc(hctx, ID_A, idlen);

    vl = DeltaTo(opctx, offset_u);
    if( x->curve->a >= 0 )
        for(t=0; t<vl->c; t++) vl->v[t] = 0;
    else vlong_cpy(vl, x->curve->p);
    vlong_adds(vl, vl, x->curve->a, 0);

    vlong_I2OSP(vl, buf, x->curve->plen);
    hfnx->updatefunc(hctx, buf, x->curve->plen);

    vlong_I2OSP(x->curve->b, buf, x->curve->plen);
    hfnx->updatefunc(hctx, buf, x->curve->plen);

    vlong_I2OSP(DeltaTo(x->curve->G, offset_x), buf, x->curve->plen);
    hfnx->updatefunc(hctx, buf, x->curve->plen);

    vlong_I2OSP(DeltaTo(x->curve->G, offset_y), buf, x->curve->plen);
    hfnx->updatefunc(hctx, buf, x->curve->plen);

    // Assume that the public key had been canonicalized

    vlong_I2OSP(DeltaTo(pubkey, offset_x), buf, x->curve->plen);
    hfnx->updatefunc(hctx, buf, x->curve->plen);

    vlong_I2OSP(DeltaTo(pubkey, offset_y), buf, x->curve->plen);
    hfnx->updatefunc(hctx, buf, x->curve->plen);

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(hctx);

    hfnx->hfinalfunc(hctx, x->uinfo, x->hlen);
}

static_assert(
    ' ' == 0x20 && '0' == 0x30 && 'A' == 0x41,
    "ASCII character set is assumed. If not, adapt code for your charset");

IntPtr SM2SIG_Keygen(
    SM2SIG_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    IntPtr ret = ECC_Keygen((ECC_Base_Ctx_Hdr_t *)x, param, prng_gen, prng);

    if( x )
    {
        x->hlen = OUT_BYTES(param[1].info);
        x->hfuncs = HASH_FUNCS_SET_INIT(param[1].info);
        x->context_type = 2;
        x->offset_hashctx = sizeof(SM2SIG_Ctx_Hdr_t);

        // the value is default per Chinese GM/T 0009-2012 section 10.
        sm2sig_setZ(x, "1234567812345678", 16);
    }

    return ret;
}

#endif /* ! PKC_OMIT_KEYGEN */

IntPtr SM2SIG_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    return ECC_Encode_PrivateKey(any, enc, enclen, param);
}

IntPtr SM2SIG_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    IntPtr ret = ECC_Decode_PrivateKey(any, enc, enclen, param);

    if( any )
    {
        SM2SIG_Ctx_Hdr_t *x = any;

        x->hlen = OUT_BYTES(param[1].info);
        x->hfuncs = HASH_FUNCS_SET_INIT(param[1].info);
        x->context_type = 2;
        x->offset_hashctx = sizeof(SM2SIG_Ctx_Hdr_t);

        // the value is default per Chinese GM/T 0009-2012 section 10.
        sm2sig_setZ(x, "1234567812345678", 16);
    }

    return ret;
}

IntPtr SM2SIG_Export_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    return ECC_Encode_PublicKey(any, enc, enclen, param);
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

IntPtr SM2SIG_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    return ECC_Encode_PublicKey(any, enc, enclen, param);
}

IntPtr SM2SIG_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    IntPtr ret = ECC_Decode_PublicKey(any, enc, enclen, param);

    if( any )
    {
        SM2SIG_Ctx_Hdr_t *x = any;

        x->hlen = OUT_BYTES(param[1].info);
        x->hfuncs = HASH_FUNCS_SET_INIT(param[1].info);
        x->context_type = 2;
        x->offset_hashctx = sizeof(SM2SIG_Ctx_Hdr_t);

        // the value is default per Chinese GM/T 0009-2012 section 10.
        sm2sig_setZ(x, "1234567812345678", 16);
    }

    return ret;
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! PKC_OMIT_PRIV_OPS

void *SM2SIG_Sign(
    SM2SIG_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng)
{
    unsigned slen = x->curve->plen < x->hlen ? x->curve->plen : x->hlen;
    uint8_t H[128] = {0}; // increased per [crypto.SE]/q/98794.

    void *restrict hctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hfnx = &x->hfuncs;

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

        break;
    }
    while( true );

    // hash the message.

    if( x->status != 3 )
    {
        x->status = 3;
        hfnx->initfunc(hctx);
        hfnx->updatefunc(hctx, x->uinfo, x->hlen);
        hfnx->updatefunc(hctx, msg, msglen);
    }

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(hctx);

    hfnx->hfinalfunc(hctx, H, slen);

    // compute r = (e + x_R) mod n

    vlong_OS2IP(
        DeltaTo(opctx, offset_v), // {v} == e
        H, slen);

    vlong_addv(
        DeltaTo(opctx, offset_r), // r == {v} + x_R == e + x_R
        DeltaTo(opctx, offset_r),
        DeltaTo(opctx, offset_v));

    vlong_remv_inplace(
        DeltaTo(opctx, offset_r),
        x->curve->n);

    vl = DeltaTo(opctx, offset_r);
    for(t=0,w=0; t<vl->c; t++)
        w |= vl->v[t];
    if( !w ) goto start; // r == 0 then goto start.

    vlong_addv(
        DeltaTo(opctx, offset_s),
        vl, k);

    vl = DeltaTo(opctx, offset_s);
    for(t=0,w=0; t<vl->c || t<x->curve->n->c; t++)
        w |= (t < vl->c ? vl->v[t] : 0) ^
            (t < x->curve->n->c ?
             x->    curve->n->v[t] : 0);
    if( !w ) goto start; // r + k == n then goto start.

    // compute s = ((1 + d_A)^-1 * (k - r * d_A)) mod n

    // s := d_A + 1
    vlong_adds(
        DeltaTo(opctx, offset_s),
        DeltaTo(x,     offset_d),
        1, 0);

    // s = s mod n
    vlong_remv_inplace(
        DeltaTo(opctx, offset_s),
        x->curve->n);

    // t := s^-1
    vlong_inv_mod_n_fermat(
        DeltaTo(opctx, offset_t),
        DeltaTo(opctx, offset_s),
        DeltaTo(opctx, offset_u),
        DeltaTo(opctx, offset_v),
        x->curve);

    // s := r * d_A
    vlong_mulv_masked(
        DeltaTo(opctx, offset_s),
        DeltaTo(opctx, offset_r),
        DeltaTo(x,     offset_d), 1,
        (vlong_modfunc_t)vlong_remv_inplace,
        x->curve->n);

    // w := k - s
    vlong_subv(
        DeltaTo(opctx, offset_w),
        k,
        DeltaTo(opctx, offset_s));

    // w := w mod n
    vlong_imod_inplace(
        DeltaTo(opctx, offset_w),
        x->curve->n);

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

void const *SM2SIG_Verify(
    SM2SIG_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen)
{
    unsigned slen = x->curve->plen < x->hlen ? x->curve->plen : x->hlen;
    uint8_t H[128] = {0}; // increased per [crypto.SE]/q/98794.

    void *restrict hctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hfnx = &x->hfuncs;

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

    hfnx->initfunc(hctx);
    hfnx->updatefunc(hctx, x->uinfo, x->hlen);
    hfnx->updatefunc(hctx, msg, msglen);

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(hctx);

    hfnx->hfinalfunc(hctx, H, slen);

    // {d} = s
    vlong_cpy(
        DeltaTo(x,     offset_d),
        DeltaTo(opctx, offset_s));

    // {k} = t = (r' + s') mod n
    vlong_addv(
        DeltaTo(x,     offset_k),
        DeltaTo(opctx, offset_r),
        DeltaTo(opctx, offset_s));

    vlong_remv_inplace(
        DeltaTo(x,     offset_k),
        x->curve->n);

    vl = DeltaTo(x, offset_k);
    for(t=0,w=0; t<vl->c; t++)
        w |= vl->v[t];
    if( !w ) goto reject;

    // (x1', y1') = s' * G + t * Q && R != O.

    ecp_xyz_inf(R);

    ecp_point_scale_accumulate(
        R, Tmp1, Tmp2, x->curve->G,
        DeltaTo(x, offset_d), // {d} == s.
        opctx, x->curve);

    ecp_point_scale_accumulate(
        R, Tmp1, Tmp2, DeltaTo(x, offset_Q),
        DeltaTo(x, offset_k), // {k} == t.
        opctx, x->curve);

    vl = DeltaTo(R, offset_z);
    for(t=0,w=0; t<vl->c; t++)
        w |= vl->v[t];
    if( !w ) goto reject; // actually, the spec didn't require this check.

    vl = DeltaTo(R, offset_x);

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

    // {v} = R = e' + x'

    vlong_OS2IP(
        DeltaTo(opctx, offset_v),
        H, slen);

    vlong_addv(
        DeltaTo(opctx, offset_r),
        DeltaTo(opctx, offset_r),
        DeltaTo(opctx, offset_v));

    // {r} = {k} - R = t - R = (r' + s') - R ==? s'

    vlong_subv(
        DeltaTo(opctx, offset_r),
        DeltaTo(x,     offset_k),
        DeltaTo(opctx, offset_r));

    vlong_imod_inplace(
        DeltaTo(opctx, offset_r),
        x->curve->n);

    if( vlong_cmpv_shifted( // {r} == {d} = s == s'
            DeltaTo(x,     offset_d),
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

void *SM2SIG_Encode_Signature(
    SM2SIG_Ctx_Hdr_t *restrict x,
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

void *SM2SIG_Sign_Xctrl(
    SM2SIG_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    (void)flags;

    switch( cmd )
    {
    case SM2SIG_set_signer_id:
        if( !bufvec || veclen < 1 ) return NULL;
        sm2sig_setZ(x, bufvec[0].dat, bufvec[0].len);
        return x;
        break;

    default:
        return NULL;
    }
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

void *SM2SIG_Decode_Signature(
    SM2SIG_Ctx_Hdr_t *restrict x,
    void const *restrict sig, size_t siglen)
{
    int subret = ber_tlv_ecc_decode_dss_signature(x, sig, siglen);
    x->status = 0;

    if( subret == -1 ) return NULL;
    else return x;
}

void *SM2SIG_Verify_Xctrl(
    SM2SIG_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    (void)flags;

    switch( cmd )
    {
    case SM2SIG_set_signer_id:
        if( !bufvec || veclen < 1 ) return NULL;
        sm2sig_setZ(x, bufvec[0].dat, bufvec[0].len);
        return x;
        break;

    default:
        return NULL;
    }
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS)

IntPtr iSM2SIG_KeyCodec(int q) { return xSM2SIG_KeyCodec(q); }

IntPtr tSM2SIG(const CryptoParam_t *P, int q)
{
    return xSM2SIG(P[0].info, P[1].info, q);
}

IntPtr iSM2SIG_CtCodec(int q) { return xSM2SIG_CtCodec(q); }

#endif /* ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS) */
