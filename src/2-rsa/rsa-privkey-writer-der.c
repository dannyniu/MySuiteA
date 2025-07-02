/* DannyNiu/NJF, 2021-04-17. Public Domain. */

#include "rsa-codec-der.h"
#include "../0-exec/struct-delta.c.h"

static IntPtr ber_tlv_encode_OtherPrimeInfos(
    BER_TLV_ENCODING_FUNC_PARAMS);

IntPtr ber_tlv_encode_RSAPrivateKey(BER_TLV_ENCODING_FUNC_PARAMS)
{
    IntPtr ret = 0, subret;

    uint8_t tlbuf[TAGLEN_MAX];
    uint8_t *ptr = tlbuf;
    IntPtr t;

    const RSA_Priv_Base_Ctx_t *bx = any;
    const RSA_Priv_Ctx_Hdr_t *ctx = any;

    uint32_t version;
    VLONG_T(1) ver;

    if( bx->count_primes_other > 0 )
        version = 1;
    else version = 0;

    ver.c = 1;
    ver.v[0] = version;

    //
    // RSAPrivateKey ::= SEQUENCE {

    //
    // version Version, -- Version ::= INTEGER ( two-prime(0), multi(1) ) --
    subret = ber_tlv_put_integer(&ver, DeltaAdd(enc, ret), enclen-ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // modulus INTEGER, -- n
    subret = ber_tlv_put_integer(
        DeltaTo(bx, offset_n), DeltaAdd(enc, ret), enclen-ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // publicExponent INTEGER, -- e
    subret = ber_tlv_put_integer(
        DeltaTo(bx, offset_e), DeltaAdd(enc, ret), enclen-ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // privateExponent INTEGER, -- d
    subret = ber_tlv_put_integer(
        DeltaTo(bx, offset_d), DeltaAdd(enc, ret), enclen-ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // prime1 INTEGER, -- p
    subret = ber_tlv_put_integer(
        DeltaTo(bx, offset_p), DeltaAdd(enc, ret), enclen-ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // prime2 INTEGER, -- q
    subret = ber_tlv_put_integer(
        DeltaTo(bx, offset_q), DeltaAdd(enc, ret), enclen-ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // exponent1 INTEGER, -- d mod (p-1)
    subret = ber_tlv_put_integer(
        DeltaTo(bx, offset_dP), DeltaAdd(enc, ret), enclen-ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // exponent2 INTEGER, -- d mod (q-1)
    subret = ber_tlv_put_integer(
        DeltaTo(bx, offset_dQ), DeltaAdd(enc, ret), enclen-ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // coefficient INTEGER, -- (inverse of q) mod p
    subret = ber_tlv_put_integer(
        DeltaTo(bx, offset_qInv), DeltaAdd(enc, ret), enclen-ret);
    if( subret < 0 ) return -1;
    ret += subret;

    if( version == 0 )
    {
        // has nothing to do.
    }
    else if( version == 1 )
    {
        //
        // otherPrimeInfos OtherPrimeInfos OPTIONAL
        // -- OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo --

        subret = ber_tlv_encode_OtherPrimeInfos(
            ctx, DeltaAdd(enc, ret), enclen-ret);
        if( subret < 0 ) return -1;
        ret += subret;
    }

    //
    // } -- End of "RSAPrivateKey ::= SEQUENCE".

    ptr += ber_put_tag(ptr, BER_TLV_TAG_UNI(16), 1);
    ptr += ber_put_len(ptr, ret);
    subret = ptr - tlbuf;

    if( enc )
    {
        if( ret + subret > (IntPtr)enclen )
            return -1;

        for(t=ret+subret; t-->subret; )
            enc[t] = enc[t - subret];

        for(t=subret; t-->0; )
            enc[t] = tlbuf[t];
    }

    return ret + subret;
}

// [2021-06-06:bug]:
// A bug was detected that caused encoding of RSA private key with
// more than 3 primes to emit incorrect result during testing of
// the RSA keygen function.
static IntPtr ber_tlv_encode_OtherPrimeInfos(
    BER_TLV_ENCODING_FUNC_PARAMS)
{
    IntPtr ret = 0, subret, accum;
    uint32_t i;

    uint8_t tlbuf[TAGLEN_MAX];
    uint8_t *ptr = tlbuf;
    IntPtr t;

    const RSA_Priv_Ctx_Hdr_t *bx = any;

    i = 0;
encode_1more_prime:
    ptr = tlbuf;
    accum = 0;
    if( i >= bx->base.count_primes_other )
    {
        ptr += ber_put_tag(ptr, BER_TLV_TAG_UNI(16), 1);
        ptr += ber_put_len(ptr, ret);
        subret = ptr - tlbuf;

        if( enc )
        {
            if( ret + subret > (IntPtr)enclen )
                return -1;

            for(t=ret+subret; t-->subret; )
                enc[t] = enc[t - subret];

            for(t=subret; t-->0; )
                enc[t] = tlbuf[t];
        }

        return ret + subret;
    }

    //
    // OtherPrimeInfo ::= SEQUENCE {

    //
    // prime INTEGER, -- r_i
    subret = ber_tlv_put_integer(
        DeltaTo(bx, primes_other[i].offset_r),
        DeltaAdd(enc, ret+accum), enclen-ret-accum);
    if( subret < 0 ) return -1;
    accum += subret;

    //
    // exponent INTEGER, -- d_i
    subret = ber_tlv_put_integer(
        DeltaTo(bx, primes_other[i].offset_d),
        DeltaAdd(enc, ret+accum), enclen-ret-accum);
    if( subret < 0 ) return -1;
    accum += subret;

    // coefficient INTEGER -- t_i
    subret = ber_tlv_put_integer(
        DeltaTo(bx, primes_other[i].offset_t),
        DeltaAdd(enc, ret+accum), enclen-ret-accum);
    if( subret < 0 ) return -1;
    accum += subret;

    //
    // } -- End of "OtherPrimeInfo ::= SEQUENCE"

    ptr += ber_put_tag(ptr, BER_TLV_TAG_UNI(16), 1);
    ptr += ber_put_len(ptr, accum);
    subret = ptr - tlbuf;

    if( enc )
    {
        if( ret + accum + subret > (IntPtr)enclen )
            return -1;

        for(t=ret+accum+subret; t-->ret+subret; )
            enc[t] = enc[t - subret];

        for(t=ret+subret; t-->ret; )
            // 2025-07-01:
            // Caused encoding to fail after the 3rd prime.
            enc[t] = tlbuf[t-ret];
    }

    ret += accum + subret;
    i++;
    goto encode_1more_prime;
}
