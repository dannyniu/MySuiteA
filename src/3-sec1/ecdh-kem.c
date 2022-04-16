/* DannyNiu/NJF, 2022-02-26. Public Domain. */

#include "ecdh-kem.h"
#include "../2-ec/ecp-pubkey-codec.h"
#include "../2-ec/curves-secp.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

#if ! PKC_OMIT_PRIV_OPS

#if ! PKC_OMIT_KEYGEN

IntPtr ECDH_KEM_Keygen(
    ECDH_KEM_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    CryptoParam_t kgparams[2] = {
        [0] = param[0],
        [1] = { .info = iECDH_Hash_Null, .param = NULL, },
    };

    return ECC_Keygen((ECC_Base_Ctx_Hdr_t *)x, kgparams, prng_gen, prng);
}

#endif /* ! PKC_OMIT_KEYGEN */

IntPtr ECDH_KEM_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    return ECC_Encode_PrivateKey(any, enc, enclen, param);
}

IntPtr ECDH_KEM_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    CryptoParam_t kgparams[2] = {
        [0] = param[0],
        [1] = { .info = iECDH_Hash_Null, .param = NULL, },
    };

    return ECC_Decode_PrivateKey(any, enc, enclen, kgparams);
}

IntPtr ECDH_KEM_Export_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    return ECC_Encode_PublicKey(any, enc, enclen, param);
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

IntPtr ECDH_KEM_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    return ECC_Encode_PublicKey(any, enc, enclen, param);
}

IntPtr ECDH_KEM_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    CryptoParam_t kgparams[2] = {
        [0] = param[0],
        [1] = { .info = iECDH_Hash_Null, .param = NULL, },
    };

    return ECC_Decode_PublicKey(any, enc, enclen, kgparams);
}

void *ECDH_KEM_Enc(
    ECDH_KEM_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng)
{
    size_t i;
    uint8_t H[128] = {0};

    vlong_size_t t;
    vlong_t *vl;
    uint32_t w;
    
    ecp_opctx_t *opctx = DeltaTo(x, offset_opctx);
    ecp_xyz_t
        *Tmp1 = DeltaTo(x, offset_Tmp1),
        *Tmp2 = DeltaTo(x, offset_Tmp2);

    ecp_xyz_t *R = DeltaTo(x, offset_R);
    vlong_t *k = DeltaTo(x, offset_k);

    // info reporting
    
    if( !ss )
    {
        *sslen = x->curve->plen;
        return NULL;
    }

    // generate 'client' keyshare.

    vl = DeltaTo(R, offset_z);

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
            R, Tmp1, Tmp2, DeltaTo(x, offset_Q),
            k, opctx, x->curve);
        
        for(t=0,w=0; t<vl->c; t++)
            w |= vl->v[t];
        if( w ) break;
        else return x->status = -1, NULL; // per SEC#1 ver.2 section 3.3.1.
    }
    while( true );

    // r = r.X / r.Z
    
    vlong_inv_mod_p_fermat(
        DeltaTo(opctx, offset_w),
        DeltaTo(R,     offset_z),
        DeltaTo(opctx, offset_u),
        DeltaTo(opctx, offset_v),
        x->curve);

    vlong_mulv_masked(
        DeltaTo(opctx, offset_r),
        DeltaTo(opctx, offset_w),
        DeltaTo(R,     offset_x), 1,
        x->curve->imod_aux->modfunc,
        x->curve->imod_aux->mod_ctx);

    // save r as octet string to {d}.

    vl = DeltaTo(x, offset_d);
    vlong_I2OSP(DeltaTo(opctx, offset_r), (void *)vl->v, x->curve->plen);

    for(i=0; i<x->curve->plen && i<*sslen; i++)
        ((uint8_t *)ss)[i] = ((uint8_t *)vl->v)[i];
    
    for(i=x->curve->plen; i<*sslen; i++)
        ((uint8_t *)ss)[i] = ((uint8_t *)vl->v)[i];

    // computing ciphertext.
    
    ecp_xyz_inf(R);
    ecp_point_scale_accumulate(
        R, Tmp1, Tmp2, x->curve->G,
        k, opctx, x->curve);

    ecc_canon_pubkey(x, DeltaTo(x, offset_R));
    return ss;
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! PKC_OMIT_PRIV_OPS

void *ECDH_KEM_Dec(
    ECDH_KEM_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen)
{
    size_t i;

    vlong_size_t t;
    vlong_t *vl;
    uint32_t w;
    
    ecp_opctx_t *opctx = DeltaTo(x, offset_opctx);
    ecp_xyz_t
        *Tmp1 = DeltaTo(x, offset_Tmp1),
        *Tmp2 = DeltaTo(x, offset_Tmp2);

    ecp_xyz_t *R = DeltaTo(x, offset_R);
    vlong_t *d = DeltaTo(x, offset_d);

    // info reporting
    
    if( !ss )
    {
        *sslen = x->curve->plen;
        return NULL;
    }

    // decapsulate.

    vl = DeltaTo(R, offset_z);

    do
    {
        ecp_xyz_copy(Tmp1, R);
        ecp_xyz_inf(R);
        ecp_point_scale_accumulate(
            R, Tmp1, Tmp2, Tmp1,
            d, opctx, x->curve);
        
        for(t=0,w=0; t<vl->c; t++)
            w |= vl->v[t];
        if( w ) break;
        else return x->status = -1, NULL; // per SEC#1 ver.2 section 3.3.1.
    }
    while( false );

    // r = r.X / r.Z
    
    vlong_inv_mod_p_fermat(
        DeltaTo(opctx, offset_w),
        DeltaTo(R,     offset_z),
        DeltaTo(opctx, offset_u),
        DeltaTo(opctx, offset_v),
        x->curve);

    vlong_mulv_masked(
        DeltaTo(opctx, offset_r),
        DeltaTo(opctx, offset_w),
        DeltaTo(R,     offset_x), 1,
        x->curve->imod_aux->modfunc,
        x->curve->imod_aux->mod_ctx);

    // save r as octet string to {k}.

    vl = DeltaTo(x, offset_k);
    vlong_I2OSP(DeltaTo(opctx, offset_r), (void *)vl->v, x->curve->plen);

    for(i=0; i<x->curve->plen && i<*sslen; i++)
        ((uint8_t *)ss)[i] = ((uint8_t *)vl->v)[i];
    
    for(i=x->curve->plen; i<*sslen; i++)
        ((uint8_t *)ss)[i] = ((uint8_t *)vl->v)[i];

    x->status = x->curve->plen;
    return ss;
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

void *ECDH_KEM_Encode_Ciphertext(
    ECDH_KEM_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t *ctlen)
{
    if( !ct )
    {
        *ctlen = 1 + x->curve->plen * 2;
        return ct;
    }

    return ecp_point_encode(
        DeltaTo(x, offset_R),
        ct, *ctlen, x->curve);
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! PKC_OMIT_PRIV_OPS

void *ECDH_KEM_Decode_Ciphertext(
    ECDH_KEM_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t ctlen)
{
    x->status = 0;

    if( ecp_point_decode(
            DeltaTo(x, offset_R),
            ct, ctlen,
            DeltaTo(x, offset_R),
            DeltaTo(x, offset_Tmp1),
            DeltaTo(x, offset_Tmp2),
            DeltaTo(x, offset_opctx),
            x->curve) )
        return x;
    else return NULL;
}

#endif /* ! PKC_OMIT_PRIV_OPS */

int ECDH_KEM_PKParams(int index, CryptoParam_t *out)
{
    switch( index )
    {
    case 0:
        return 1;
        break;

    case 1:
        out[0].info = i_secp256r1;
        out[0].param = NULL;
        return 128;
        break;

    case 2:
        out[0].info = i_secp384r1;
        out[0].param = NULL;
        return 192;
        break;

    default:
        return 0;
    }
}

#if ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS)

IntPtr iECDH_KEM_KeyCodec(int q) { return xECDH_KEM_KeyCodec(q); }

IntPtr tECDH_KEM(const CryptoParam_t *P, int q)
{
    return xECDH_KEM(P[0].info, q);
}

IntPtr iECDH_KEM_CtCodec(int q) { return xECDH_KEM_CtCodec(q); }

#endif /* ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS) */
