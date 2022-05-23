/* DannyNiu/NJF, 2021-02-13. Public Domain. */

#include "rsa-codec-der.h"
#include "../0-exec/struct-delta.c.h"

#define BER_HDR ber_get_hdr(&ptr, &remain, &tag, &len)

static IntPtr ber_tlv_decode_OtherPrimeInfos(
    BER_TLV_DECODING_FUNC_PARAMS,
    int pass, IntPtr addr, uint32_t *count_primes_other);

IntPtr ber_tlv_decode_RSAPrivateKey(BER_TLV_DECODING_FUNC_PARAMS)
{
    int pass = any ? 2 : 1;
    int pass_saved = pass;
    IntPtr ret = 0, subret;

    const uint8_t *ptr = enc;
    size_t remain = enclen;
    uint32_t i;

    uint32_t tag;
    size_t len;

    RSA_Priv_Base_Ctx_t *bx = any;
    RSA_Priv_Ctx_Hdr_t *ctx = any;

    uint32_t count_primes_other;
    int32_t size_modulus;

    uint32_t version;

    pass = 1;
    bx = NULL;
    ctx = NULL;
decode_rsa_priv_key:

    //
    // RSAPrivateKey ::= SEQUENCE {
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(16) ) return -1;

    //
    // version Version, -- Version ::= INTEGER ( two-prime(0), multi(1) ) --
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    for(i=0, version = 0; i<len; i++) version = (version << 8) | ptr[i];
    ptr += len; remain -= len;

    if( pass == 2 )
    {
        bx->count_primes_other = count_primes_other;
    }

    //
    // modulus INTEGER, -- n
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;
    if( pass == 2 )
    {
        bx->offset_n =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    }

    size_modulus = ber_tlv_decode_integer(DeltaTo(bx, offset_n), ptr, len);
    if( pass == 2 )  bx->modulus_bits = vlong_topbit(DeltaTo(bx, offset_n));
    ret += size_modulus;
    ptr += len; remain -= len;

    // 2021-09-12:
    // There was a serious error similar to
    // that in "rsa-pubkey-codec-der.c"
    // found yesterday.

    if( pass == 2 )
        bx->offset_w1 =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    ret += size_modulus;

    if( pass == 2 )
        bx->offset_w2 =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    ret += size_modulus;

    if( pass == 2 )
        bx->offset_w3 =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    ret += size_modulus;

    if( pass == 2 )
        bx->offset_w4 =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    ret += size_modulus;

    if( pass == 2 )
        bx->offset_w5 =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    ret += size_modulus;

    if( pass == 2 )
    {
        ((vlong_t *)DeltaTo(bx, offset_w1))->c = size_modulus / 4 - 1;
        ((vlong_t *)DeltaTo(bx, offset_w2))->c = size_modulus / 4 - 1;
        ((vlong_t *)DeltaTo(bx, offset_w3))->c = size_modulus / 4 - 1;
        ((vlong_t *)DeltaTo(bx, offset_w4))->c = size_modulus / 4 - 1;
        ((vlong_t *)DeltaTo(bx, offset_w5))->c = size_modulus / 4 - 1;
    }

    //
    // publicExponent INTEGER, -- e
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    if( pass == 2 )
    {
        bx->offset_e =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    }

    ret += ber_tlv_decode_integer(DeltaTo(bx, offset_e), ptr, len);
    ptr += len; remain -= len;

    //
    // privateExponent INTEGER, -- d
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    if( pass == 2 )
    {
        bx->offset_d =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    }

    ret += ber_tlv_decode_integer(DeltaTo(bx, offset_d), ptr, len);
    ptr += len; remain -= len;

    //
    // prime1 INTEGER, -- p
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    if( pass == 2 )
    {
        bx->offset_p =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    }

    ret += ber_tlv_decode_integer(DeltaTo(bx, offset_p), ptr, len);
    ptr += len; remain -= len;

    //
    // prime2 INTEGER, -- q
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    if( pass == 2 )
    {
        bx->offset_q =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    }

    ret += ber_tlv_decode_integer(DeltaTo(bx, offset_q), ptr, len);
    ptr += len; remain -= len;

    //
    // exponent1 INTEGER, -- d mod (p-1)
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    if( pass == 2 )
    {
        bx->offset_dP =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    }

    ret += ber_tlv_decode_integer(DeltaTo(bx, offset_dP), ptr, len);
    ptr += len; remain -= len;

    //
    // exponent2 INTEGER, -- d mod (q-1)
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    if( pass == 2 )
    {
        bx->offset_dQ =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    }

    ret += ber_tlv_decode_integer(DeltaTo(bx, offset_dQ), ptr, len);
    ptr += len; remain -= len;

    //
    // coefficient INTEGER, -- (inverse of q) mod p
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    if( pass == 2 )
    {
        bx->offset_qInv =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other +
            ret; // it's been tracking occupied space since pass 1.
    }

    ret += ber_tlv_decode_integer(DeltaTo(bx, offset_qInv), ptr, len);
    ptr += len; remain -= len;

    // 2022-05-23:
    // assertion added to make linter more accurate.
    assert( version == 0 || version == 1 );

    if( version == 0 )
    {
        count_primes_other = 0;
    }
    else if( version == 1 )
    {
        //
        // otherPrimeInfos OtherPrimeInfos OPTIONAL
        // -- OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo --

        if( -1 == BER_HDR ) return -1;
        if( tag != BER_TLV_TAG_UNI(16) ) return -1;

        subret = ber_tlv_decode_OtherPrimeInfos(
            ctx, ptr, len,
            pass, ret, &count_primes_other);

        if( subret == -1 ) return -1;
        ret += subret;
        ptr += len; remain -= len;
    }

    //
    // } -- End of "RSAPrivateKey ::= SEQUENCE".
    ret +=
        sizeof(RSA_Priv_Base_Ctx_t) +
        sizeof(RSA_OtherPrimeInfo_t) * count_primes_other;

    if( pass_saved == 2 && pass == 1 )
    {
        pass = 2;
        bx = any;
        ctx = any;
        ret = 0;
        ptr = enc;
        remain = enclen;
        goto decode_rsa_priv_key;
    }

    return ret;
}

static IntPtr ber_tlv_decode_OtherPrimeInfos(
    BER_TLV_DECODING_FUNC_PARAMS,
    int pass, IntPtr addr, uint32_t *count_primes_other)
{
    IntPtr ret = 0;

    const uint8_t *ptr = enc;
    size_t remain = enclen;
    uint32_t i;

    uint32_t tag;
    size_t len;

    RSA_Priv_Ctx_Hdr_t *bx = any;

    i = 0;
decode_1more_prime:
    if( pass == 1 )
    {
        if( !remain )
        {
            *count_primes_other = i;
            return ret;
        }
    }
    else if( pass == 2 )
    {
        if( i >= *count_primes_other )
            return ret;
    }
    else return -1;

    //
    // OtherPrimeInfo ::= SEQUENCE {
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(16) ) return -1;

    //
    // prime INTEGER, -- r_i
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    if( pass == 2 )
    {
        bx->primes_other[i].offset_r =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->base.count_primes_other +
            addr + ret; // it's been tracking occupied space since pass 1.
    }

    ret += ber_tlv_decode_integer(
        DeltaTo(bx, primes_other[i].offset_r), ptr, len);
    ptr += len; remain -= len;

    //
    // exponent INTEGER, -- d_i
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    if( pass == 2 )
    {
        bx->primes_other[i].offset_d =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->base.count_primes_other +
            addr + ret; // it's been tracking occupied space since pass 1.
    }

    ret += ber_tlv_decode_integer(
        DeltaTo(bx, primes_other[i].offset_d), ptr, len);
    ptr += len; remain -= len;

    // coefficient INTEGER -- t_i
    if( -1 == BER_HDR ) return -1;
    if( tag != BER_TLV_TAG_UNI(2) ) return -1;

    if( pass == 2 )
    {
        bx->primes_other[i].offset_t =
            sizeof(RSA_Priv_Base_Ctx_t) +
            sizeof(RSA_OtherPrimeInfo_t) * bx->base.count_primes_other +
            addr + ret; // it's been tracking occupied space since pass 1.
    }

    ret += ber_tlv_decode_integer(
        DeltaTo(bx, primes_other[i].offset_t), ptr, len);
    ptr += len; remain -= len;

    //
    // } -- End of "OtherPrimeInfo ::= SEQUENCE"
    i++;
    goto decode_1more_prime;
}
