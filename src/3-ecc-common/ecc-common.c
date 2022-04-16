/* DannyNiu/NJF, 2022-02-11. Public Domain. */

#include "ecc-common.h"
#include "../2-ec/ecp-pubkey-codec.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

IntPtr iECDH_Hash_Null(int q) { (void)q; return ECDH_HASH_NULL(q); }

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

void ecc_canon_pubkey(
    ECC_Base_Ctx_Hdr_t *restrict x,
    ecp_xyz_t *restrict Q)
{
    ecp_opctx_t *opctx = DeltaTo(x, offset_opctx);

    // canonicalize.
    // 2022-04-16: remember not to touch r and s.

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

static void ecc_ctxinit_basic(
    ECC_Base_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param)
{
    const ecp_curve_t *curve = (const void *)param[0].info(ptrCurveDef);
    unsigned bits = curve->plen * 8;

    *x = ECC_CTX_INIT(
        ECC_Base_Ctx_Hdr_t,
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

#if ! PKC_OMIT_PRIV_OPS

#if ! PKC_OMIT_KEYGEN

static void ecc_gen_privkey(
    ECC_Base_Ctx_Hdr_t *restrict x,
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

    ecc_canon_pubkey(x, DeltaTo(x, offset_Q));
}

IntPtr ECC_Keygen(
    ECC_Base_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    if( !x ) return ECC_CTX_SIZE(param[0].info, param[1].info); else
    {
        ecc_ctxinit_basic(x, param);
        ecc_gen_privkey((void *)x, prng_gen, prng);
        return (IntPtr)x;
    }
}

#endif /* ! PKC_OMIT_KEYGEN */

static void *ecc_dec_privkey(
    ECC_Base_Ctx_Hdr_t *restrict x,
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

    ecc_canon_pubkey(x, DeltaTo(x, offset_Q));

    return x;
}

IntPtr ECC_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    ECC_Base_Ctx_Hdr_t const *x = any;
    (void)param;

    if( enc )
    {
        if( enclen != x->curve->plen ) return -1;
        vlong_I2OSP(DeltaTo(x, offset_d), enc, x->curve->plen);
    }
    return x->curve->plen;
}

IntPtr ECC_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    ECC_Base_Ctx_Hdr_t *x = any;

    if( any )
    {
        ecc_ctxinit_basic(x, param);

        if( !ecc_dec_privkey(any, enc, enclen) )
            return -1;
    }
    return ECC_CTX_SIZE(param[0].info, param[1].info);
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS && ! PKC_OMIT_PRIV_OPS

#if ! PKC_OMIT_PRIV_OPS

IntPtr ECC_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    ECC_Base_Ctx_Hdr_t const *x = any;
    (void)param;

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

IntPtr ber_tlv_ecc_encode_dss_signature(BER_TLV_ENCODING_FUNC_PARAMS)
{
    int pass = enc ? 2 : 1;
    IntPtr ret = 0, subret;

    uint8_t *stack = NULL;
    uint8_t *ptr = enc;
    size_t remain = enclen;
    //- not used -// uint32_t i;

    size_t taglen;

    const ECC_Hash_Ctx_Hdr_t *ctx = any;
    const ecp_opctx_t *opctx = DeltaTo(ctx, offset_opctx);

    //
    // Ecdsa-Sig-Value ::= SEQUENCE {

    //
    // r INTEGER,
           subret = ber_tlv_encode_integer(DeltaTo(opctx, offset_r), ptr, remain);
    ret += subret;

    if( pass == 2 ) stack = enc + enclen; // [NULL-stack-in-pass-1].
    taglen = 0;
    taglen += ber_push_len(&stack, subret);
    taglen += ber_push_tag(&stack, BER_TLV_TAG_UNI(2), 0);

    if( pass == 2 )
    {
        ber_util_splice_insert(ptr, subret, (stack - ptr), taglen);
    }
    ret += taglen;
    if( enc ) ptr += subret + taglen; remain -= subret + taglen;

    //
    // s INTEGER,
           subret = ber_tlv_encode_integer(DeltaTo(opctx, offset_s), ptr, remain);
    ret += subret;

    if( pass == 2 ) stack = enc + enclen; // [NULL-stack-in-pass-1].
    taglen = 0;
    taglen += ber_push_len(&stack, subret);
    taglen += ber_push_tag(&stack, BER_TLV_TAG_UNI(2), 0);

    if( pass == 2 )
    {
        ber_util_splice_insert(ptr, subret, (stack - ptr), taglen);
    }
    ret += taglen;
    if( enc ) ptr += subret + taglen; remain -= subret + taglen;

    //
    // } -- End of "Ecdsa-Sig-Value ::= SEQUENCE".

    if( pass == 2 ) stack = enc + enclen;
    taglen = 0;
    taglen += ber_push_len(&stack, ret);
    taglen += ber_push_tag(&stack, BER_TLV_TAG_UNI(16), 1);

    if( pass == 2 )
    {
        ber_util_splice_insert(enc, ret, (stack - enc), taglen);
    }
    ret += taglen;

    return ret;
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#define BER_HDR ber_get_hdr(&ptr, &remain, &tag, &len)

int ber_tlv_ecc_decode_dss_signature(BER_TLV_DECODING_FUNC_PARAMS)
{
    // 2021-02-13: refer to
    // [ber-int-err-chk:2021-02-13] in "2-asn1/der-codec.c".

    // int pass = any ? 2 : 1; // not used.
    // IntPtr ret = 0; // not used.

    const uint8_t *ptr = enc;
    size_t remain = enclen;

    uint32_t tag;
    size_t len;

    ECC_Hash_Ctx_Hdr_t *ctx = any;
    ecp_opctx_t *opctx = DeltaTo(ctx, offset_opctx);

    //
    // Ecdsa-Sig-Value ::= SEQUENCE {
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(16) ) return -1;

    //
    // r INTEGER,
           if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    vlong_OS2IP(DeltaTo(opctx, offset_r), ptr, len);
    ptr += len; remain -= len;

    //
    // s INTEGER,
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    vlong_OS2IP(DeltaTo(opctx, offset_s), ptr, len);
    ptr += len; remain -= len;

    //
    // } -- End of "Ecdsa-Sig-Value ::= SEQUENCE".

    // The size of working context for ECDSA
    // cannot be estimated from its signatures.
    return 0;
}

#endif /* ! PKC_OMIT_PUB_OPS && ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

IntPtr ECC_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    ECC_Base_Ctx_Hdr_t *x = any;
    const ecp_curve_t *curve = (const void *)param[0].info(ptrCurveDef);

    if( any )
    {
        ecc_ctxinit_basic(x, param);

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
    return ECC_CTX_SIZE(param[0].info, param[1].info);
}

#endif /* ! PKC_OMIT_PUB_OPS */
