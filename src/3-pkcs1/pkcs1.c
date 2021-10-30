/* DannyNiu/NJF, 2021-09-12. Public Domain. */

#include "pkcs1.h"
#include "../2-rsa/rsa-codec-der.h"

#if ! (PKCS1_OMIT_KEYGEN || PKCS1_OMIT_PRIV_OPS)

IntPtr PKCS1_Keygen(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    IntPtr ret;
    
    if( x )
    {
        *x = PKCS1_PRIV_CTX_INIT(
            param[0].info, param[1].info, param[2].aux,
            param[3].aux, param[4].aux);
    }

    ret = rsa_keygen(
        x ? (void *)((uint8_t *)x + x->offset_rsa_privctx) : NULL,
        param + 3, prng_gen, prng);

    if( !ret ) return 0;
    else if( x ) return (IntPtr)x;
    else
    {
        ret += sizeof(PKCS1_Priv_Ctx_Hdr_t);
        ret += PKCS1_HASH_CTX_SIZE(param[0].info, param[1].info);
        return ret;
    }
}

#endif /* ! (PKCS1_OMIT_KEYGEN || PKCS1_OMIT_PRIV_OPS) */

#if ! PKCS1_OMIT_PRIV_OPS

int32_t PKCS1_Encode_RSAPrivateKey(BER_TLV_ENCODING_FUNC_PARAMS)
{
    const PKCS1_Priv_Ctx_Hdr_t *x = any;
    aux = NULL;
    
    return ber_tlv_encode_RSAPrivateKey(
        pass, enc, enclen, 
        x ? (void *)((uint8_t *)x + x->offset_rsa_privctx) : NULL,
        NULL);
}

int32_t PKCS1_Decode_RSAPrivateKey(BER_TLV_DECODING_FUNC_PARAMS)
{
    PKCS1_Priv_Ctx_Hdr_t *x = any;
    PKCS1_Codec_Aux_t *ap = aux;
    CryptoParam_t *po = ap->aux_po;
    int32_t ret;

    if( x )
    {
        *x = PKCS1_PRIV_CTX_INIT(
            po[0].info, po[1].info, po[2].aux,
            0, 0); // these 2 arguments are not used by this macro.
    }

    ret = ber_tlv_decode_RSAPrivateKey(
        pass, enc, enclen,
        x ? (void *)((uint8_t *)x + x->offset_rsa_privctx) : NULL,
        &ap->aux_misc);

    if( ret < 0 ) return ret;

    ret += sizeof(PKCS1_Priv_Ctx_Hdr_t);
    ret += PKCS1_HASH_CTX_SIZE(po[0].info, po[1].info);

    return ret;
}

int32_t PKCS1_Encode_RSAPublicKey(BER_TLV_ENCODING_FUNC_PARAMS)
{
    // 2021-10-30:
    // This function erroneously used the public context when
    // public key are generated on and could only be exported
    // from a private context. A fix had been applied.
    
    const PKCS1_Priv_Ctx_Hdr_t *x = any;
    aux = NULL;
    
    return ber_tlv_encode_RSAPublicKey(
        pass, enc, enclen, 
        x ? (void *)((uint8_t *)x + x->offset_rsa_privctx) : NULL,
        NULL);
}

#endif /* ! PKCS1_OMIT_PRIV_OPS */

#if ! PKCS1_OMIT_PUB_OPS

int32_t PKCS1_Decode_RSAPublicKey(BER_TLV_DECODING_FUNC_PARAMS)
{
    PKCS1_Pub_Ctx_Hdr_t *x = any;
    PKCS1_Codec_Aux_t *ap = aux;
    CryptoParam_t *po = ap->aux_po;
    int32_t ret;

    if( x )
    {
        *x = PKCS1_PUB_CTX_INIT(
            po[0].info, po[1].info, po[2].aux,
            0); // this argument is not used by this macro.
    }
    
    ret = ber_tlv_decode_RSAPublicKey(
        pass, enc, enclen,
        x ? (void *)((uint8_t *)x + x->offset_rsa_pubctx) : NULL,
        &ap->aux_misc);

    if( ret < 0 ) return ret;

    ret += sizeof(PKCS1_Pub_Ctx_Hdr_t);
    ret += PKCS1_HASH_CTX_SIZE(po[0].info, po[1].info);
    
    return ret;
}

#endif /* ! PKCS1_OMIT_PUB_OPS */
