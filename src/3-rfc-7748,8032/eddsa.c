/* DannyNiu/NJF, 2022-05-05. Public Domain. */

#include "eddsa-misc.h"
#include "../2-ec/curves-Ed.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

static void HashDom(
    EdDSA_Ctx_Hdr_t *restrict x,
    hash_funcs_set_t *restrict hfnx,
    void *dst, size_t *t, size_t plen)
{
    uint8_t cc[1];

    if( plen == 32 )
    {
        if( x->flags & EdDSA_Flags_PH || x->ctxstr[0] > 0 )
        {
            hfnx->updatefunc(
                dst, "SigEd25519 no Ed25519 collisions", 32);

            cc[0] = x->flags & EdDSA_Flags_PH;
            hfnx->updatefunc(dst, cc, 1);
            hfnx->updatefunc(dst, x->ctxstr, x->ctxstr[0] + 1);

            if( t ) *t += 32 + 2 + x->ctxstr[0];
        }
        // else t += 0; // 2024-03-17: nop, commented out.
    }
    else // plen must be 57.
    {
        x->hfuncs.updatefunc(dst, "SigEd448", 8);

        cc[0] = x->flags & EdDSA_Flags_PH;
        hfnx->updatefunc(dst, cc, 1);
        hfnx->updatefunc(dst, x->ctxstr, x->ctxstr[0] + 1);

        if( t ) *t += 8 + 2 + x->ctxstr[0];
    }
}

static void *Ed25519_Set_DomainParams(
    EdDSA_Ctx_Hdr_t *restrict x,
    const bufvec_t *restrict bufvec)
{
    // void *dst = DeltaTo(x, offset_hashctx_init);
    // uint8_t bi[2];
    size_t t;

    x->flags = bufvec[0].info;

    if( x->flags & EdDSA_Flags_PH || bufvec[1].len )
    {
        if( bufvec[1].len > 255 ) return NULL;
        x->ctxstr[0] = bufvec[1].len;

        for(t=0; t<bufvec[1].len; t++)
            x->ctxstr[t+1] = ((const uint8_t *)bufvec[1].dat)[t];
    }
    else
    {
        x->ctxstr[0] = 0;
    }

    return x;
}

static void *Ed448_Set_DomainParams(
    EdDSA_Ctx_Hdr_t *restrict x,
    const bufvec_t *restrict bufvec)
{
    // void *dst = DeltaTo(x, offset_hashctx_init);
    // uint8_t bi[2];
    size_t t;

    x->flags = bufvec[0].info;

    if( bufvec[1].len > 255 ) return NULL;
    x->ctxstr[0] = bufvec[1].len;

    for(t=0; t<bufvec[1].len; t++)
        x->ctxstr[t+1] = ((const uint8_t *)bufvec[1].dat)[t];
    return x;
}

#if ! PKC_OMIT_PRIV_OPS

#if ! PKC_OMIT_KEYGEN

IntPtr EdDSA_Keygen(
    EdDSA_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    ecEd_curve_t const *curve = (void const *)param[0].info(ecEd_PtrCurveDef);
    size_t plen = (curve->pbits + 8) / 8;

    if( !x ) return EDDSA_CTX_SIZE(param[0].info, param[1].info); else
    {
        eddsa_ctxinit_basic(x, param);
        prng_gen(prng, x->sk, plen);

        eddsa_privkey_reload(x);
        return (IntPtr)x;
    }
}

#endif /* ! PKC_OMIT_KEYGEN */

IntPtr EdDSA_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    EdDSA_Ctx_Hdr_t const *x = any;
    size_t plen = (x->curve->pbits + 8) / 8;
    (void)param;

    if( enc )
    {
        if( enclen != plen ) return -1;
        for(plen=0; plen<enclen; plen++)
            ((uint8_t *)enc)[plen] = x->sk[plen];
    }
    return plen;
}

IntPtr EdDSA_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    EdDSA_Ctx_Hdr_t *x = any;
    ecEd_curve_t const *curve = (void const *)param[0].info(ecEd_PtrCurveDef);
    size_t plen = (curve->pbits + 8) / 8;

    if( any )
    {
        if( enclen != plen ) return -1;
        eddsa_ctxinit_basic(x, param);

        for(plen=0; plen<enclen; plen++)
            x->sk[plen] = ((const uint8_t *)enc)[plen];

        eddsa_privkey_reload(x);
    }
    return EDDSA_CTX_SIZE(param[0].info, param[1].info);
}

#endif /* ! PKC_OMIT_PRIV_OPS */

IntPtr EdDSA_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    EdDSA_Ctx_Hdr_t const *x = any;
    size_t plen = (x->curve->pbits + 8) / 8;
    (void)param;

    if( enc )
    {
        if( plen != enclen ) return -1;
        eddsa_point_enc(x, enc, DeltaTo(x, offset_A));
    }

    return plen;
}

#if ! PKC_OMIT_PUB_OPS

IntPtr EdDSA_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    EdDSA_Ctx_Hdr_t *x = any;
    ecEd_curve_t const *curve = (void const *)param[0].info(ecEd_PtrCurveDef);
    size_t plen = (curve->pbits + 8) / 8;

    if( any )
    {
        if( enclen != plen ) return -1;
        eddsa_ctxinit_basic(x, param);

        if( !eddsa_point_dec(x, enc, DeltaTo(x, offset_A)) )
        {
            x->status = -1;
            return -1;
        }
    }

    return EDDSA_CTX_SIZE(param[0].info, param[1].info);
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! PKC_OMIT_PRIV_OPS

void *EdDSA_Sign(
    EdDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng)
{
    uint8_t *dst;
    // uint8_t const *src;
    uint8_t hmsg[64];
    uint8_t buf[256];
    size_t plen = (x->curve->pbits + 8) / 8;
    size_t t, b;

    hash_funcs_set_t *hfnx = &x->hfuncs;
    ecEd_opctx_t *opctx = DeltaTo(x, offset_opctx);

    assert( plen == 32 || plen == 57 );

    // was 16 before 2023-11-17, which is so small that
    // it caused error/bug.
    VLONG_T(32) e = { .c = 32 };

    dst = DeltaTo(x, offset_hashctx);
    // src = DeltaTo(x, offset_hashctx_init);

    // Step 2.
    // 2023-05-19: was: H(dom(F,C) + prefix + PH(M), plen)
    // 2023-11-16: changed to: H(dom(F,C) + Z + prefix + 000... + PH(M), plen)
    // 2024-03-17: changed to:
    // H(00h + Z + dom(F,C) + 000... + prefix + 000... + PH(M), plen)

    // Updated Step 2: PH(M). // brought here to avoid schedule conflict.

    if( x->flags & EdDSA_Flags_PH )
    {
        hfnx->initfunc(dst);
        hfnx->updatefunc(dst, msg, msglen);

        if( hfnx->xfinalfunc )
            hfnx->xfinalfunc(dst);

        // [2023-05-19:outlen-64]:
        // ``64'' isn't mistaken. RFC-8032 says
        // "PH is SHA512" for Ed25519ph, and
        // "PH being SHAKE256(x, 64)" for Ed448ph.
        hfnx->hfinalfunc(dst, hmsg, 64);
    }

    // Updated Step 2: 00h and then 'Z'.

    for(t=0; t<sizeof(buf); t++)
        buf[t] = 0;

    if( prng_gen && prng )
        prng_gen(prng, buf+1, plen);

    hfnx->updatefunc(dst, buf, plen+1);
    t = plen+1;

    // Updated Step 2: DOM String.

    HashDom(x, hfnx, dst, &t, plen);

    // Updated Step 2: 000...

    b = plen == 32 ? 128 : plen == 57 ? 136 : 1;
    t %= b;
    t = b - t;

    for(b=0; b<t; b++) buf[b] = 0;
    hfnx->updatefunc(dst, buf, t);

    // Updated Step 2: 'prefix'.

    hfnx->updatefunc(dst, x->prefix, plen);
    t = plen;

    // Updated Step 2: 000...

    b = plen == 32 ? 128 : plen == 57 ? 136 : 1;
    t %= b;
    t = b - t;

    for(b=0; b<t; b++) buf[b] = 0;
    hfnx->updatefunc(dst, buf, t);

    // Updated Step 2: PH(M)

    if( x->flags & EdDSA_Flags_PH )
    {
        hfnx->updatefunc(dst, hmsg, 64);
    }
    else hfnx->updatefunc(dst, msg, msglen);

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(dst);

    hfnx->hfinalfunc(dst, buf, plen * 2);

    // R = [r]B

    vlong_DecLSB((vlong_t *)&e, buf, plen * 2);
    vlong_remv_inplace((vlong_t *)&e, x->curve->L);
    vlong_cpy(DeltaTo(x, offset_r), (vlong_t *)&e);

    ecEd_xytz_inf(DeltaTo(x, offset_R));
    ecEd_point_scale_accumulate(
        DeltaTo(x, offset_R),
        DeltaTo(x, offset_Tmp1),
        DeltaTo(x, offset_Tmp2),
        x->curve->B,
        DeltaTo(x, offset_r),
        opctx, x->curve);

    // H(dom(F,C) + R + A + PH(M), plen * 2)

    /* for(t=0; t<x->hashctx_size; t++)
       dst[t] = src[t]; */
    hfnx->initfunc(dst);
    HashDom(x, hfnx, dst, NULL, plen);

    eddsa_canon_pubkey(x, DeltaTo(x, offset_R));
    eddsa_point_enc(x, buf, DeltaTo(x, offset_R));
    hfnx->updatefunc(dst, buf, plen);

    eddsa_point_enc(x, buf, DeltaTo(x, offset_A));
    hfnx->updatefunc(dst, buf, plen);

    if( x->flags & EdDSA_Flags_PH )
    {
        // pre-hash flag is set.
        hfnx->updatefunc(dst, hmsg, 64);
    }
    else
    {
        // pre-hash flag is clear.
        hfnx->updatefunc(dst, msg, msglen);
    }

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(dst);
    hfnx->hfinalfunc(dst, buf, plen * 2);

    // {ctx.r} := S = (r + k * s)

    vlong_DecLSB((vlong_t *)&e, buf, plen * 2);
    vlong_remv_inplace((vlong_t *)&e, x->curve->L);
    vlong_cpy(DeltaTo(opctx, offset_r), (vlong_t *)&e);

    vlong_mulv_masked(
        DeltaTo(opctx, offset_w),
        DeltaTo(opctx, offset_r),
        DeltaTo(x,     offset_s), 1,
        (vlong_modfunc_t)
        vlong_remv_inplace,
        x->curve->L);

    vlong_addv(
        DeltaTo(x, offset_r),
        DeltaTo(x, offset_r),
        DeltaTo(opctx, offset_w));

    vlong_remv_inplace(DeltaTo(x, offset_r), x->curve->L);

    // 2023-07-01:
    // status value 2 was added in the "2023-hedged-dss" branch;
    // the following line was forgotten, and as such, reusing
    // the same EdDSA working context for signing multiple messages
    // may fail unpredictably.
    x->status = 1;

    return x;
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

void const *EdDSA_Verify(
    EdDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen)
{
    uint8_t *dst;
    //uint8_t const *src;
    uint8_t hmsg[64];
    uint8_t buf[128];
    size_t plen = (x->curve->pbits + 8) / 8;
    //size_t t;

    hash_funcs_set_t *hfnx = &x->hfuncs;
    ecEd_opctx_t *opctx = DeltaTo(x, offset_opctx);

    // was 16 before 2023-11-17, which is so small that
    // it caused error/bug.
    VLONG_T(32) e = { .c = 32 };
    vlong_size_t i;

    if( x->status )
    {
        if( x->status > 0 ) return msg;
        else return NULL;
    }

    dst = DeltaTo(x, offset_hashctx);
    // src = DeltaTo(x, offset_hashctx_init);

    // H(dom(F,C) + R + A + PH(M), plen * 2)

    // 2023-11-16:
    // moved here to fix the conflict schedule bug/error.

    if( x->flags & EdDSA_Flags_PH )
    {
        // pre-hash flag is set.

        hfnx->initfunc(dst);
        hfnx->updatefunc(dst, msg, msglen);
        if( hfnx->xfinalfunc )
            hfnx->xfinalfunc(dst);
        hfnx->hfinalfunc(dst, hmsg, 64);
    }

    /* for(t=0; t<x->hashctx_size; t++)
       dst[t] = src[t]; */
    hfnx->initfunc(dst);
    HashDom(x, hfnx, dst, NULL, plen);

    // here in verification, this is the decoded one, already canon.
    // eddsa_canon_pubkey(x, DeltaTo(x, offset_R));
    eddsa_point_enc(x, buf, DeltaTo(x, offset_R));
    hfnx->updatefunc(dst, buf, plen);

    // also already canon.
    eddsa_point_enc(x, buf, DeltaTo(x, offset_A));
    hfnx->updatefunc(dst, buf, plen);

    if( x->flags & EdDSA_Flags_PH )
    {
        // pre-hash flag is set.
        hfnx->updatefunc(dst, hmsg, 64);
    }
    else
    {
        // pre-hash flag is clear.
        hfnx->updatefunc(dst, msg, msglen);
    }

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(dst);
    hfnx->hfinalfunc(dst, buf, plen * 2);

    // {ctx.s} := k
    vlong_DecLSB((vlong_t *)&e, buf, plen * 2);
    vlong_remv_inplace((vlong_t *)&e, x->curve->L);
    vlong_cpy(DeltaTo(x, offset_s), (vlong_t *)&e);

    // {ctx.R} += [k]A
    ecEd_point_scale_accumulate(
        DeltaTo(x, offset_R),
        DeltaTo(x, offset_Tmp1),
        DeltaTo(x, offset_Tmp2),
        DeltaTo(x, offset_A),
        DeltaTo(x, offset_s),
        opctx, x->curve);

    eddsa_canon_pubkey(x, DeltaTo(x, offset_R));
    eddsa_point_enc(x, x->sk, DeltaTo(x, offset_R));

    ecEd_xytz_inf(DeltaTo(x, offset_R));

    // add [S]B to the negated R.
    ecEd_point_scale_accumulate(
        DeltaTo(x, offset_R),
        DeltaTo(x, offset_Tmp1),
        DeltaTo(x, offset_Tmp2),
        x->curve->B,
        DeltaTo(x, offset_r),
        opctx, x->curve);

    eddsa_canon_pubkey(x, DeltaTo(x, offset_R));
    eddsa_point_enc(x, x->prefix, DeltaTo(x, offset_R));

    for(buf[0]=0,i=0; i<plen; i++)
    {
        buf[0] |= x->sk[i] ^ x->prefix[i];
    }

    if( buf[0] )
    {
        x->status = -1;
        return NULL;
    }

    x->status = 1;
    return msg;
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! PKC_OMIT_PRIV_OPS

void *EdDSA_Encode_Signature(
    EdDSA_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen)
{
    unsigned pbits = x->curve->pbits;
    size_t plen = (pbits + 8) / 8;

    IntPtr minlen = plen * 2;

    if( !sig )
    {
        *siglen = minlen;
        return NULL;
    }

    if( *siglen < (size_t)minlen ) return NULL;

    eddsa_point_enc(x, sig, DeltaTo(x, offset_R));

    vlong_EncLSB(DeltaTo(x, offset_r), (uint8_t *)sig + plen, plen);

    return sig;
}

void *EdDSA_Sign_Xctrl(
    EdDSA_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    (void)flags;

    switch( cmd )
    {
    case EdDSA_set_domain_params:
        if( !bufvec || veclen < 2 ) return NULL;

        if( x->curve == CurveEd25519 )
            return Ed25519_Set_DomainParams(x, bufvec);

        if( x->curve == CurveEd448 )
            return Ed448_Set_DomainParams(x, bufvec);

        return x;
        break;

    default:
        return NULL;
    }
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

void *EdDSA_Decode_Signature(
    EdDSA_Ctx_Hdr_t *restrict x,
    void const *restrict sig, size_t siglen)
{
    unsigned pbits = x->curve->pbits;
    size_t plen = (pbits + 8) / 8;

    void *subret = x;
    x->status = 0;

    if( subret )
    {
        if( plen * 2 != siglen )
            subret = NULL;
    }

    if( subret )
    {
        subret = eddsa_point_dec(
            x, sig, DeltaTo(x, offset_R));
    }

    if( subret )
    {
        vlong_DecLSB(
            DeltaTo(x, offset_r),
            (const uint8_t *)sig + plen, plen);

        if( vlong_cmpv_shifted(
                DeltaTo(x, offset_r),
                x->curve->L, 0) != 2 )
            subret = NULL;
    }

    if( !subret )
    {
        x->status = -1;
        return NULL;
    }
    else return x; // status set to 0 at the beginning.
}

void *EdDSA_Verify_Xctrl(
    EdDSA_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    (void)flags;

    switch( cmd )
    {
    case EdDSA_set_domain_params:
        if( !bufvec || veclen < 2 ) return NULL;

        if( x->curve == CurveEd25519 )
            return Ed25519_Set_DomainParams(x, bufvec);

        if( x->curve == CurveEd448 )
            return Ed448_Set_DomainParams(x, bufvec);

        return x;
        break;

    default:
        return NULL;
    }
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS)

IntPtr iEdDSA_KeyCodec(int q) { return xEdDSA_KeyCodec(q); }

IntPtr tEdDSA(const CryptoParam_t *P, int q)
{
    return xEdDSA(P[0].info, P[1].info, q);
}

IntPtr iEdDSA_CtCodec(int q) { return xEdDSA_CtCodec(q); }

#endif /* ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS) */
