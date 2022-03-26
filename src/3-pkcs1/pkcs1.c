/* DannyNiu/NJF, 2021-09-12. Public Domain. */

#include "pkcs1.h"
#include "../2-rsa/rsa-codec-der.h"
#include "../0-exec/struct-delta.c.h"

#if ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS)

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
        DeltaTo(x, offset_rsa_privctx),
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

#endif /* ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS) */

#if ! PKC_OMIT_PRIV_OPS

IntPtr PKCS1_Encode_RSAPrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    const PKCS1_Priv_Ctx_Hdr_t *x = any;
    (void)param;

    return ber_tlv_encode_RSAPrivateKey(
        DeltaTo(x, offset_rsa_privctx), enc, enclen);
}

IntPtr PKCS1_Decode_RSAPrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    PKCS1_Priv_Ctx_Hdr_t *x = any;
    IntPtr ret;

    if( x )
    {
        *x = PKCS1_PRIV_CTX_INIT(
            param[0].info, param[1].info, param[2].aux,
            param[3].aux, param[4].aux); // 2 ignored parameters.
    }

    ret = ber_tlv_decode_RSAPrivateKey(
        DeltaTo(x, offset_rsa_privctx), enc, enclen);

    if( ret < 0 ) return ret;

    ret += sizeof(PKCS1_Priv_Ctx_Hdr_t);
    ret += PKCS1_HASH_CTX_SIZE(param[0].info, param[1].info);

    return ret;
}

IntPtr PKCS1_Export_RSAPublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    // 2021-10-30:
    // This function erroneously used the public context when
    // public key are generated on and could only be exported
    // from a private context. A fix had been applied.

    const PKCS1_Priv_Ctx_Hdr_t *x = any;
    (void)param;

    return ber_tlv_export_RSAPublicKey(
        DeltaTo(x, offset_rsa_privctx), enc, enclen);
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

IntPtr PKCS1_Encode_RSAPublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    // 2021-10-30:
    // This function erroneously used the public context when
    // public key are generated on and could only be exported
    // from a private context. A fix had been applied.

    const PKCS1_Pub_Ctx_Hdr_t *x = any;
    (void)param;

    return ber_tlv_encode_RSAPublicKey(
        DeltaTo(x, offset_rsa_pubctx), enc, enclen);
}

IntPtr PKCS1_Decode_RSAPublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param)
{
    PKCS1_Pub_Ctx_Hdr_t *x = any;
    IntPtr ret;

    if( x )
    {
        *x = PKCS1_PUB_CTX_INIT(
            param[0].info, param[1].info, param[2].aux,
            param[3].aux, param[4].aux); // 2 ignored parameters.
    }

    ret = ber_tlv_decode_RSAPublicKey(
        DeltaTo(x, offset_rsa_pubctx), enc, enclen);

    if( ret < 0 ) return ret;

    ret += sizeof(PKCS1_Pub_Ctx_Hdr_t);
    ret += PKCS1_HASH_CTX_SIZE(param[0].info, param[1].info);

    return ret;
}

#endif /* ! PKC_OMIT_PUB_OPS */

#include "../2-hash/sha.h"

int PKCS1_PKParams(int index, CryptoParam_t *out)
{
    switch( index )
    {
    case 0:
        return 5;
        break;

    case 1:
        out[0].info = iSHA256;
        out[1].info = iSHA256;
        out[2].info = NULL;
        out[3].info = NULL;
        out[4].info = NULL;
        out[0].param = NULL;
        out[1].param = NULL;
        out[2].aux = 32;
        out[3].aux = 2048;
        out[4].aux = 2;
        return 112;
        break;

    default:
        return 0;
    }
}

#if ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS)
IntPtr iPKCS1_KeyCodec(int q) { return xPKCS1_KeyCodec(q); }
#endif /* ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS) */
