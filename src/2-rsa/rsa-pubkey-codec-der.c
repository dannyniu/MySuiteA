/* DannyNiu/NJF, 2021-02-13. Public Domain. */

#include "rsa-codec-der.h"
#include "../0-exec/struct-delta.c.h"

#define BER_HDR ber_get_hdr(&ptr, &remain, &tag, &len)

int32_t ber_tlv_decode_RSAPublicKey(BER_TLV_DECODING_FUNC_PARAMS)
{
    // 2021-02-13: refer to
    // [ber-int-err-chk:2021-02-13] in "2-asn1/der-parse.c".
    
    int32_t ret = 0;
    
    const uint8_t *ptr = enc;
    size_t remain = enclen;

    uint32_t tag, len;

    RSA_Pub_Ctx_Hdr_t *ctx = any;

    int32_t size_modulus;

    aux = NULL;

    //
    // RSAPublicKey ::= SEQUENCE {
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(16) ) return -1;

    //
    // modulus INTEGER, -- n
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    if( pass == 2 )
    {
        ctx->offset_n =
            sizeof(RSA_Pub_Ctx_Hdr_t) +
            ret; // it's been tracking occupied space since pass 1.
    }
    
    size_modulus = ber_tlv_decode_integer(
        pass, ptr, len,
        DeltaTo(ctx, offset_n),
        ctx ? &ctx->modulus_bits : NULL);
    ret += size_modulus;
    ptr += len; remain -= len;

    // 2021-09-11:
    // There was a serious error in which
    // pass 1 gives wrong estimate.
    
    if( pass == 2 )
        ctx->offset_w1 = 
            sizeof(RSA_Pub_Ctx_Hdr_t) +
            ret; // it's been tracking occupied space since pass 1.
    ret += size_modulus;

    if( pass == 2 )
        ctx->offset_w2 = 
            sizeof(RSA_Pub_Ctx_Hdr_t) +
            ret; // it's been tracking occupied space since pass 1.
    ret += size_modulus;
        
    if( pass == 2 )
        ctx->offset_w3 = 
            sizeof(RSA_Pub_Ctx_Hdr_t) +
            ret; // it's been tracking occupied space since pass 1.
    ret += size_modulus;
        
    if( pass == 2 )
        ctx->offset_w4 = 
            sizeof(RSA_Pub_Ctx_Hdr_t) +
            ret; // it's been tracking occupied space since pass 1.
    ret += size_modulus;
        
    if( pass == 2 )
    {
        ((vlong_t *)DeltaTo(ctx, offset_w1))->c = size_modulus / 4 - 1;
        ((vlong_t *)DeltaTo(ctx, offset_w2))->c = size_modulus / 4 - 1;
        ((vlong_t *)DeltaTo(ctx, offset_w3))->c = size_modulus / 4 - 1;
        ((vlong_t *)DeltaTo(ctx, offset_w4))->c = size_modulus / 4 - 1;
    }
    
    //
    // publicExponent INTEGER, -- e
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    if( pass == 2 )
    {
        ctx->offset_e =
            sizeof(RSA_Pub_Ctx_Hdr_t) +
            ret; // it's been tracking occupied space since pass 1.
    }
    
    ret += ber_tlv_decode_integer(
        pass, ptr, len,
        DeltaTo(ctx, offset_e), NULL);
    ptr += len; remain -= len;

    //
    // } -- End of "RSAPublicKey ::= SEQUENCE".
    ret += sizeof(RSA_Pub_Ctx_Hdr_t);

    return ret;
}

int32_t ber_tlv_encode_RSAPublicKey(BER_TLV_ENCODING_FUNC_PARAMS)
{
    int32_t ret = 0, subret;

    uint8_t *stack = NULL;
    uint8_t *ptr = enc;
    size_t remain = enclen;
    //- not used -// uint32_t i;

    uint32_t taglen;
    
    const RSA_Priv_Base_Ctx_t *ctx = any;

    aux = NULL;

    //
    // RSAPublicKey ::= SEQUENCE {
    //- if( -1 == BER_HDR ) return -1;
    //- if( tag != BER_TLV_TAG_UNI(16) ) return -1;

    //
    // modulus INTEGER, -- n
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        DeltaTo(ctx, offset_n), NULL);
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
    ptr += subret + taglen; remain -= subret + taglen;
    
    //
    // publicExponent INTEGER, -- e
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        DeltaTo(ctx, offset_e), NULL);
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
    ptr += subret + taglen; remain -= subret + taglen;
    
    //
    // } -- End of "RSAPublicKey ::= SEQUENCE".
    
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
