/* DannyNiu/NJF, 2021-02-13. Public Domain. */

#include "rsa-codec-der.h"
#include "../0-exec/struct-delta.c.h"

#define BER_HDR ber_get_hdr(&ptr, &remain, &tag, &len)

IntPtr ber_tlv_decode_RSAPublicKey(BER_TLV_DECODING_FUNC_PARAMS)
{
    // 2021-02-13: refer to
    // [ber-int-err-chk:2021-02-13] in "2-asn1/der-codec.c".

    int pass = any ? 2 : 1;
    IntPtr ret = 0;
    
    const uint8_t *ptr = enc;
    size_t remain = enclen;

    uint32_t tag;
    size_t len;

    RSA_Pub_Ctx_Hdr_t *ctx = any;

    int32_t size_modulus;

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
    
    size_modulus = ber_tlv_decode_integer(DeltaTo(ctx, offset_n), ptr, len);
    if( pass == 2 )  ctx->modulus_bits = vlong_topbit(DeltaTo(ctx, offset_n));
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
    
    ret += ber_tlv_decode_integer(DeltaTo(ctx, offset_e), ptr, len);
    ptr += len; remain -= len;

    //
    // } -- End of "RSAPublicKey ::= SEQUENCE".
    ret += sizeof(RSA_Pub_Ctx_Hdr_t);

    return ret;
}
