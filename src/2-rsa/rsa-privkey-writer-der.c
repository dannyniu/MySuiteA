/* DannyNiu/NJF, 2021-04-17. Public Domain. */

#include "rsa-codec-der.h"
#include "../0-exec/struct-delta.c.h"

static int32_t ber_tlv_encode_OtherPrimeInfos(BER_TLV_ENCODING_FUNC_PARAMS);

int32_t ber_tlv_encode_RSAPrivateKey(BER_TLV_ENCODING_FUNC_PARAMS)
{
    int32_t ret = 0, subret;

    uint8_t *stack = NULL;
    uint8_t *ptr = enc;
    size_t remain = enclen;
    //- not used -// uint32_t i;

    uint32_t taglen;
    
    const RSA_Priv_Base_Ctx_t *bx = any;
    const RSA_Priv_Ctx_Hdr_t *ctx = any;

    uint32_t version;
    VLONG_T(1) ver;

    aux = NULL;

    if( bx->count_primes_other > 0 )
        version = 1;
    else version = 0;
    
    ver.c = 1;
    ver.v[0] = version;

    //
    // RSAPrivateKey ::= SEQUENCE {
    //- if( -1 == BER_HDR ) return -1;
    //- if( tag != BER_TLV_TAG_UNI(16) ) return -1;

    //
    // version Version, -- Version ::= INTEGER ( two-prime(0), multi(1) ) --
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        &ver, NULL);
    ret += subret;

    // [NULL-stack-in-pass-1]:
    // stack is initialized as NULL and only set to non-NULL in pass-2 when
    // actual tag and length values are to be pushed onto the stack.
    // this avoids NULL-resetting in pass 1 and saves one if clause.
    if( pass == 2 ) stack = enc + enclen;
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
    // modulus INTEGER, -- n
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        DeltaTo(bx, offset_n), NULL);
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
        DeltaTo(bx, offset_e), NULL);
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
    // privateExponent INTEGER, -- d
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        DeltaTo(bx, offset_d), NULL);
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
    // prime1 INTEGER, -- p
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        DeltaTo(bx, offset_p), NULL);
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
    // prime2 INTEGER, -- q
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        DeltaTo(bx, offset_q), NULL);
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
    // exponent1 INTEGER, -- d mod (p-1)
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        DeltaTo(bx, offset_dP), NULL);
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
    // exponent2 INTEGER, -- d mod (q-1)
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        DeltaTo(bx, offset_dQ), NULL);
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
    // coefficient INTEGER, -- (inverse of q) mod p
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        DeltaTo(bx, offset_qInv), NULL);
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
    
    if( version == 0 )
    {
        // do nothing.
    }
    else if( version == 1 )
    {
        //
        // otherPrimeInfos OtherPrimeInfos OPTIONAL
        // -- OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo --
        
        subret = ber_tlv_encode_OtherPrimeInfos(
            pass, ptr, remain,
            ctx, NULL);
        ret += subret;

        if( pass == 2 ) stack = enc + enclen;
        taglen = 0;
        taglen += ber_push_len(&stack, subret);
        taglen += ber_push_tag(&stack, BER_TLV_TAG_UNI(16), 1);

        if( pass == 2 )
        {
            ber_util_splice_insert(ptr, subret, (stack - ptr), taglen);
        }
        ret += taglen;
        ptr += subret + taglen; remain -= subret + taglen;
    
    }

    //
    // } -- End of "RSAPrivateKey ::= SEQUENCE".
    
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

// [2021-06-06:bug]:
// A bug was detected that caused encoding of RSA private key with
// more than 3 primes to emit incorrect result during testing of
// the RSA keygen function.
static int32_t ber_tlv_encode_OtherPrimeInfos(BER_TLV_ENCODING_FUNC_PARAMS)
{
    int32_t ret = 0, subret, accum;

    uint8_t *stack = NULL;
    uint8_t *ptr = enc;
    uint8_t *ptr1;
    size_t remain = enclen;
    uint32_t i;

    uint32_t taglen;

    const RSA_Priv_Ctx_Hdr_t *bx = any;

    aux = NULL;

    i = 0;
encode_1more_prime:
    if( pass == 1 || pass == 2 )
    {
        if( i >= bx->base.count_primes_other )
            return ret;
    }
    else return -1;

    //
    // OtherPrimeInfo ::= SEQUENCE {
    ptr1 = ptr;
    accum = 0;

    //
    // prime INTEGER, -- r_i
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        DeltaTo(bx, primes_other[i].offset_r), NULL);
    accum += subret;

    if( pass == 2 ) stack = enc + enclen; // [NULL-stack-in-pass-1].
    taglen = 0;
    taglen += ber_push_len(&stack, subret);
    taglen += ber_push_tag(&stack, BER_TLV_TAG_UNI(2), 0);
    
    if( pass == 2 )
    {
        ber_util_splice_insert(ptr, subret, (stack - ptr), taglen);
    }
    accum += taglen;
    ptr += subret + taglen; remain -= subret + taglen;
    
    //
    // exponent INTEGER, -- d_i
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        DeltaTo(bx, primes_other[i].offset_d), NULL);
    accum += subret;

    if( pass == 2 ) stack = enc + enclen; // [NULL-stack-in-pass-1].
    taglen = 0;
    taglen += ber_push_len(&stack, subret);
    taglen += ber_push_tag(&stack, BER_TLV_TAG_UNI(2), 0);
    
    if( pass == 2 )
    {
        ber_util_splice_insert(ptr, subret, (stack - ptr), taglen);
    }
    accum += taglen;
    ptr += subret + taglen; remain -= subret + taglen;
    
    // coefficient INTEGER -- t_i
    subret = ber_tlv_encode_integer(
        pass, ptr, remain,
        DeltaTo(bx, primes_other[i].offset_t), NULL);
    accum += subret;

    if( pass == 2 ) stack = enc + enclen; // [NULL-stack-in-pass-1].
    taglen = 0;
    taglen += ber_push_len(&stack, subret);
    taglen += ber_push_tag(&stack, BER_TLV_TAG_UNI(2), 0);
    
    if( pass == 2 )
    {
        ber_util_splice_insert(ptr, subret, (stack - ptr), taglen);
    }
    accum += taglen;
    ptr += subret + taglen; remain -= subret + taglen;
    
    //
    // } -- End of "OtherPrimeInfo ::= SEQUENCE"
    
    if( pass == 2 ) stack = enc + enclen;
    taglen = 0;
    taglen += ber_push_len(&stack, accum);
    taglen += ber_push_tag(&stack, BER_TLV_TAG_UNI(16), 1);

    if( pass == 2 )
    {
        ber_util_splice_insert(ptr1, accum, (stack - ptr1), taglen);
    }
    ptr += taglen; // [2021-06-06:bug]: was caused by the missing of this line.
    ret += accum + taglen; remain -= taglen;
    
    i++;
    goto encode_1more_prime;
}
