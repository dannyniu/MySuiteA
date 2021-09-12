/* DannyNiu/NJF, 2021-09-12. Public Domain. */

#include "pkcs1.h"
#include "../2-rsa/rsa-codec-der.h"

IntPtr PKCS1_Keygen(
    PKCS1_Private_Context_t *restrict x,
    PKCS1_Private_Param_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    IntPtr ret;
    PKCS1_Padding_Oracles_Param_t *po = &param->params_po;
    
    if( x )
    {
        *x = PKCS1_PRIVATE_CONTEXT_INIT(
            PKCS1_PRIVATE_PARAM_DETUPLE(*param));
    }

    ret = rsa_keygen(
        x ? (void *)((uint8_t *)x + x->offset_rsa_privctx) : NULL,
        &param->params_rsa, prng_gen, prng);

    if( !ret ) return 0;
    else if( x ) return (IntPtr)x;
    else
    {
        ret += sizeof(PKCS1_Private_Context_t);
        ret += PKCS1_HASH_CTX_SIZE(
            po->hash_msg,
            po->hash_mgf);
        return ret;
    }
}

int32_t PKCS1_Encode_RSAPrivateKey(BER_TLV_ENCODING_FUNC_PARAMS)
{
    const PKCS1_Private_Context_t *x = any;
    aux = NULL;
    
    return ber_tlv_encode_RSAPrivateKey(
        pass, enc, enclen, 
        x ? (void *)((uint8_t *)x + x->offset_rsa_privctx) : NULL,
        NULL);
}

int32_t PKCS1_Decode_RSAPrivateKey(BER_TLV_DECODING_FUNC_PARAMS)
{
    PKCS1_Codec_Aux_t *ap = aux;
    PKCS1_Padding_Oracles_Param_t *po = &ap->aux_po;
    PKCS1_Private_Context_t *x = any;
    int32_t ret;

    if( x )
    {
        *x = PKCS1_PRIVATE_CONTEXT_INIT(
            0,0, // these 2 arguments are not used by this macro.
            po->hash_msg,
            po->hash_mgf,
            po->saltlen);
    }

    ret = ber_tlv_decode_RSAPrivateKey(
        pass, enc, enclen,
        x ? (void *)((uint8_t *)x + x->offset_rsa_privctx) : NULL,
        &ap->aux_misc);

    if( ret < 0 ) return ret;

    ret += sizeof(PKCS1_Private_Context_t);
    ret += PKCS1_HASH_CTX_SIZE(
        po->hash_msg,
        po->hash_mgf);

    return ret;
}

int32_t PKCS1_Encode_RSAPublicKey(BER_TLV_ENCODING_FUNC_PARAMS)
{
    const PKCS1_Public_Context_t *x = any;
    aux = NULL;
    
    return ber_tlv_encode_RSAPublicKey(
        pass, enc, enclen, 
        x ? (void *)((uint8_t *)x + x->offset_rsa_pubctx) : NULL,
        NULL);
}

int32_t PKCS1_Decode_RSAPublicKey(BER_TLV_DECODING_FUNC_PARAMS)
{
    PKCS1_Codec_Aux_t *ap = aux;
    PKCS1_Padding_Oracles_Param_t *po = &ap->aux_po;
    PKCS1_Public_Context_t *x = any;
    int32_t ret;

    if( x )
    {
        *x = PKCS1_PUBLIC_CONTEXT_INIT(
            0, // this argument is not used by this macro.
            po->hash_msg,
            po->hash_mgf,
            po->saltlen);
    }
    
    ret = ber_tlv_decode_RSAPublicKey(
        pass, enc, enclen,
        x ? (void *)((uint8_t *)x + x->offset_rsa_pubctx) : NULL,
        &ap->aux_misc);

    if( ret < 0 ) return ret;

    ret += sizeof(PKCS1_Public_Context_t);
    ret += PKCS1_HASH_CTX_SIZE(
        po->hash_msg,
        po->hash_mgf);
    
    return ret;
}
