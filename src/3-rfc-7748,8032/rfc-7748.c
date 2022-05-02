/* DannyNiu/NJF, 2022-04-27. Public Domain. */

#include "xecdh.h.h"
#include "../0-exec/struct-delta.c.h"

static inline void stubprng(void *restrict ctx, void *restrict out, size_t len)
{
    size_t i;
    for(i=0; i<len; i++) ((uint8_t *)out)[i] = ((const uint8_t *)ctx)[i];
}

#if ! PKC_OMIT_PRIV_OPS

#if ! PKC_OMIT_KEYGEN

IntPtr glue(XECDH,_Keygen)(
    XECDH_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    vlong_t *k, *K;
    vlong_size_t t;
    
    (void)param;
    
    if( !x ) return XECDH_CTX_SIZE(CRV_BITS); else
    {
        *x = XECDH_CTX_HDR_INIT(CRV_BITS);
        
        x->status = 0;
        x->imod_aux = modp;
        
        ecMt_opctx_init(DeltaTo(x, offset_opctx), CRV_BITS);
        ((vlong_t *)DeltaTo(x, offset_k))->c = VLONG_BITS_WCNT(CRV_BITS);
        ((vlong_t *)DeltaTo(x, offset_K))->c = VLONG_BITS_WCNT(CRV_BITS);
        ((vlong_t *)DeltaTo(x, offset_P))->c = VLONG_BITS_WCNT(CRV_BITS);
        
        k = DeltaTo(x, offset_k);
        K = DeltaTo(x, offset_K);

        K->v[0] = U_P;
        for(t=1; t<K->c; t++) K->v[t] = 0;

        xecdh_gen_scl(
            k, K, DeltaTo(x, offset_opctx),
            x->imod_aux, prng_gen, prng);
        
        return (IntPtr)x;
    }
}

#endif /* ! PKC_OMIT_KEYGEN */

IntPtr glue(XECDH,_Encode_PrivateKey)(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    XECDH_Ctx_Hdr_t const *x = any;
    (void)param;

    if( enc )
    {
        if( enclen != SSLEN ) return -1;
        vlong_EncLSB(DeltaTo(x, offset_k), enc, enclen);
    }
    return SSLEN;
}

IntPtr glue(XECDH,_Decode_PrivateKey)(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    XECDH_Ctx_Hdr_t *x = any;
    
    if( any )
    {
        if( enclen != SSLEN ) return -1;

        // 2022-04-28:
        // ``enc'' is const-qualified, where as the param is not.
        // cast to silence a warning, which had been noted.
        glue(XECDH,_Keygen)(x, param, stubprng, (void *)enc);
    }
    return XECDH_CTX_SIZE(CRV_BITS);
}

#endif /* ! PKC_OMIT_PRIV_OPS */

IntPtr glue(XECDH,_Encode_PublicKey)(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    XECDH_Ctx_Hdr_t const *x = any;
    (void)param;

    if( enc )
    {
        if( enclen != SSLEN ) return -1;
        vlong_EncLSB(DeltaTo(x, offset_K), enc, enclen);
    }
    return SSLEN;
}

#if ! PKC_OMIT_PUB_OPS

IntPtr glue(XECDH,_Decode_PublicKey)(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    XECDH_Ctx_Hdr_t *restrict x = any;
    vlong_t *vl;
    (void)param;

    if( any )
    {
        *x = XECDH_CTX_HDR_INIT(CRV_BITS);
        
        x->status = 0;
        x->imod_aux = modp;
        
        ecMt_opctx_init(DeltaTo(x, offset_opctx), CRV_BITS);
        ((vlong_t *)DeltaTo(x, offset_k))->c = VLONG_BITS_WCNT(CRV_BITS);
        ((vlong_t *)DeltaTo(x, offset_K))->c = VLONG_BITS_WCNT(CRV_BITS);
        ((vlong_t *)DeltaTo(x, offset_P))->c = VLONG_BITS_WCNT(CRV_BITS);
        
        vl = DeltaTo(x, offset_K);
        vlong_DecLSB(vl, enc, enclen);
        
#if A24 == ((486662 - 2) / 4) && U_P == 9 && SSLEN == 32
        vl->v[7] &= INT32_MAX;
#endif /* This is Curve 25519. */
    }
    return XECDH_CTX_SIZE(CRV_BITS);
}

void *glue(XECDH,_Enc)(
    XECDH_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng)
{
    vlong_t *k, *K, *P;
    ecMt_opctx_t *opctx;
 
    uint8_t tmp[SSLEN];
    size_t t;

    if( !ss )
    {
        *sslen = SSLEN;
        return NULL;
    }
    
    k = DeltaTo(x, offset_k);
    K = DeltaTo(x, offset_K);
    P = DeltaTo(x, offset_P);
    opctx = DeltaTo(x, offset_opctx);

    vlong_cpy(P, K);

    xecdh_gen_scl(
        k, P, opctx,
        x->imod_aux,
        prng_gen, prng);

    vlong_EncLSB(P, tmp, SSLEN);

    for(t=0; t<*sslen && t<SSLEN; t++)
        ((uint8_t *)ss)[t] = tmp[t];

    for(; t<*sslen; t++)
        ((uint8_t *)ss)[t] = 0;

    P->v[0] = U_P; // set generator value.
    for(t=1; t<P->c; t++) P->v[t] = 0;
    
    ecMt_point_scale(
        k, P, A24, CRV_BITS,
        opctx, x->imod_aux);

    return ss;
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! PKC_OMIT_PRIV_OPS

void *glue(XECDH,_Dec)(
    XECDH_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen)
{
    vlong_t *k, *P;
    ecMt_opctx_t *opctx;
 
    uint8_t tmp[SSLEN];
    size_t t;

    if( x->status > 0 )
    {
    finish:
        if( ss )
        {
            vlong_EncLSB(P, tmp, SSLEN);

            for(t=0; t<*sslen && t<SSLEN; t++)
                ((uint8_t *)ss)[t] = tmp[t];

            for(; t<*sslen; t++)
                ((uint8_t *)ss)[t] = 0;

            return ss;
        }
        else
        {
            *sslen = SSLEN;
            return NULL;
        }
    }
    
    k = DeltaTo(x, offset_k);
    P = DeltaTo(x, offset_P);
    opctx = DeltaTo(x, offset_opctx);

    ecMt_point_scale(
        k, P, A24, CRV_BITS,
        opctx, x->imod_aux);

    x->status = SSLEN;
    goto finish;
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

void *glue(XECDH,_Encode_Ciphertext)(
    XECDH_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t *ctlen)
{
    if( !ct ) *ctlen = SSLEN;
    else if( *ctlen != SSLEN ) return NULL;
    else vlong_EncLSB(DeltaTo(x, offset_P), ct, *ctlen);
    
    return ct;
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! PKC_OMIT_PRIV_OPS

void *glue(XECDH,_Decode_Ciphertext)(
    XECDH_Ctx_Hdr_t *restrict x,
    void const *restrict ct, size_t ctlen)
{
    vlong_t *vl = DeltaTo(x, offset_P);
    
    x->status = 0;
    vlong_DecLSB(vl, ct, ctlen);

#if A24 == ((486662 - 2) / 4) && U_P == 9 && SSLEN == 32
    vl->v[7] &= INT32_MAX;
#endif /* This is Curve 25519. */
    
    return x;
}

#endif /* ! PKC_OMIT_PRIV_OPS */
