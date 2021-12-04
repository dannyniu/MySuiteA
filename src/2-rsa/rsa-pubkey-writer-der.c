/* DannyNiu/NJF, 2021-02-13. Public Domain. */

#include "rsa-codec-der.h"
#include "../0-exec/struct-delta.c.h"

IntPtr ber_tlv_encode_RSAPublicKey(BER_TLV_ENCODING_FUNC_PARAMS)
{
    int pass = enc ? 2 : 1;
    IntPtr ret = 0, subret;

    uint8_t *stack = NULL;
    uint8_t *ptr = enc;
    size_t remain = enclen;
    //- not used -// uint32_t i;

    size_t taglen;
    
    const RSA_Pub_Ctx_Hdr_t *ctx = any;

    //
    // RSAPublicKey ::= SEQUENCE {

    //
    // modulus INTEGER, -- n
    subret = ber_tlv_encode_integer(DeltaTo(ctx, offset_n), ptr, remain);
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
    // publicExponent INTEGER, -- e
    subret = ber_tlv_encode_integer(DeltaTo(ctx, offset_e), ptr, remain);
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
