/* DannyNiu/NJF, 2022-05-05. Public Domain. */

#include "eddsa-misc.h"
#include "../2-ec/curves-Ed.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

static const char *DomStr25519 = "SigEd25519 no Ed25519 collisions";
static const char *DomStr448 = "SigEd448";

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

static void *RFC8032_Sign(
    EdDSA_Ctx_Hdr_t *restrict x, uint8_t flags,
    void const *restrict em, size_t emlen,
    GenFunc_t prng_gen, void *restrict prng);

void *EdDSA_Sign(
    EdDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng)
{
    x->status = 0;
    return RFC8032_Sign(x, 0, msg, msglen, prng_gen, prng);
}

void *EdDSA_IncSign_Init(
    EdDSA_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback)
{
    void *restrict hctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hfnx = &x->hfuncs;

    x->status = 0;
    hfnx->initfunc(hctx);
    *placeback = hfnx->updatefunc;
    return hctx;
}

void *EdDSA_IncSign_Final(
    EdDSA_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen,
    void *restrict prng)
{
    uint8_t em[64];
    void *restrict hctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hfnx = &x->hfuncs;

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(hctx);

    hfnx->hfinalfunc(hctx, em, 64);
    return RFC8032_Sign(x, 1, em, 64, prng_gen, prng);
}

static void *RFC8032_Sign(
    EdDSA_Ctx_Hdr_t *restrict x, uint8_t flags,
    void const *restrict em, size_t emlen,
    GenFunc_t prng_gen, void *restrict prng)
{
    uint8_t *dst; // was initialized by copying from a "src", hence the name.
    uint8_t buf[128];
    size_t plen = (x->curve->pbits + 8) / 8;

    hash_funcs_set_t *hfnx = &x->hfuncs;
    ecEd_opctx_t *opctx = DeltaTo(x, offset_opctx);

    // was 16 before 2023-11-17, which is so small that
    // it caused error/bug.
    VLONG_T(32) e = { .c = 32 };

#if true
    (void)prng_gen;
    (void)prng;
#endif // implementing deterministic EdDSA, currently.

    dst = DeltaTo(x, offset_hashctx);

    // H(dom(F,C) + prefix + PH(M), plen)

    hfnx->initfunc(dst);

    if( plen != 32 || x->ctxstr[0] > 0 || flags )
    {
        // Added 2024-10-06 as part of the
        // new domain separation string initialization routine.

        if( plen == 32 )
            hfnx->updatefunc(dst, DomStr25519, 32);
        else hfnx->updatefunc(dst, DomStr448, 8);

        hfnx->updatefunc(dst, &flags, 1);
        hfnx->updatefunc(dst, x->ctxstr, x->ctxstr[0]+1);
    }

    hfnx->updatefunc(dst, x->prefix, plen);
    hfnx->updatefunc(dst, em, emlen);

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

    hfnx->initfunc(dst);

    if( plen != 32 || x->ctxstr[0] > 0 || flags )
    {
        // Added 2024-10-06 as part of the
        // new domain separation string initialization routine.

        if( plen == 32 )
            hfnx->updatefunc(dst, DomStr25519, 32);
        else hfnx->updatefunc(dst, DomStr448, 8);

        hfnx->updatefunc(dst, &flags, 1);
        hfnx->updatefunc(dst, x->ctxstr, x->ctxstr[0]+1);
    }

    eddsa_canon_pubkey(x, DeltaTo(x, offset_R));
    eddsa_point_enc(x, buf, DeltaTo(x, offset_R));
    hfnx->updatefunc(dst, buf, plen);

    eddsa_point_enc(x, buf, DeltaTo(x, offset_A));
    hfnx->updatefunc(dst, buf, plen);

    hfnx->updatefunc(dst, em, emlen);

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

    return x;
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

static bool RFC8032_Verify(
    EdDSA_Ctx_Hdr_t *restrict x, uint8_t flags,
    void const *restrict em, size_t emlen);

void const *EdDSA_Verify(
    EdDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen)
{
    if( x->status == 1 ) return msg;
    if( x->status == -1 ) return NULL;

    if( RFC8032_Verify(x, 0, msg, msglen) )
        return msg;
    else return NULL;
}

void *EdDSA_IncVerify_Init(
    EdDSA_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback)
{
    void *restrict hctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hfnx = &x->hfuncs;

    x->status = 0;
    hfnx->initfunc(hctx);
    *placeback = hfnx->updatefunc;
    return hctx;
}

void *EdDSA_IncVerify_Final(
    EdDSA_Ctx_Hdr_t *restrict x)
{
    uint8_t em[64];
    void *restrict hctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hfnx = &x->hfuncs;

    if( x->status == 1 ) return x;
    if( x->status == -1 ) return NULL;

    if( x->status )
    {
        if( x->status == 1 ) return x;
        else return NULL;
    }

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(hctx);

    hfnx->hfinalfunc(hctx, em, 64);
    if( RFC8032_Verify(x, 1, em, 64) )
        return x;
    else return NULL;
}

static bool RFC8032_Verify(
    EdDSA_Ctx_Hdr_t *restrict x, uint8_t flags,
    void const *restrict em, size_t emlen)
{
    uint8_t *dst; // was initialized by copying from a "src", hence the name.
    uint8_t buf[128];
    size_t plen = (x->curve->pbits + 8) / 8;

    hash_funcs_set_t *hfnx = &x->hfuncs;
    ecEd_opctx_t *opctx = DeltaTo(x, offset_opctx);

    // was 16 before 2023-11-17, which is so small that
    // it caused error/bug.
    VLONG_T(32) e = { .c = 32 };
    vlong_size_t i;

    dst = DeltaTo(x, offset_hashctx);

    // H(dom(F,C) + R + A + PH(M), plen * 2)

    hfnx->initfunc(dst);

    if( plen != 32 || x->ctxstr[0] > 0 || flags )
    {
        // Added 2024-10-06 as part of the
        // new domain separation string initialization routine.

        if( plen == 32 )
            hfnx->updatefunc(dst, DomStr25519, 32);
        else hfnx->updatefunc(dst, DomStr448, 8);

        hfnx->updatefunc(dst, &flags, 1);
        hfnx->updatefunc(dst, x->ctxstr, x->ctxstr[0]+1);
    }

    // here in verification, this is the decoded one, already canon.
    // eddsa_canon_pubkey(x, DeltaTo(x, offset_R));
    eddsa_point_enc(x, buf, DeltaTo(x, offset_R));
    hfnx->updatefunc(dst, buf, plen);

    // also already canon.
    eddsa_point_enc(x, buf, DeltaTo(x, offset_A));
    hfnx->updatefunc(dst, buf, plen);

    hfnx->updatefunc(dst, em, emlen);

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
        return false;
    }

    x->status = 1;
    return true;
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
    size_t t;
    (void)flags;

    switch( cmd )
    {
    case EdDSA_set_ctxstr:
        if( !bufvec || veclen < 1 ) return NULL;
        if( bufvec[0].len > 255 ) return NULL;

        x->ctxstr[0] = bufvec[0].len;
        for(t=0; t<bufvec[0].len; t++)
            x->ctxstr[t+1] = ((uint8_t *)bufvec[0].dat)[t];
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
    size_t t;
    (void)flags;

    switch( cmd )
    {
    case EdDSA_set_ctxstr:
        if( !bufvec || veclen < 1 ) return NULL;
        if( bufvec[0].len > 255 ) return NULL;

        x->ctxstr[0] = bufvec[0].len;
        for(t=0; t<bufvec[0].len; t++)
            x->ctxstr[t+1] = ((uint8_t *)bufvec[0].dat)[t];
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
