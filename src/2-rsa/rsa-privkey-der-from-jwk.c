/* DannyNiu/NJF, 2025-06-22. Public Domain. */

#include "rsa-codec-jwk.h"
#include "../2-asn1/der-codec.h"
#include "../0-exec/struct-delta.c.h"

static IntPtr OtherPrimeInfo_FromJsonObject(
    json_io_t jstr, uint8_t *enc, size_t enclen)
{
    IntPtr subret, accum;
    uint8_t tlbuf[TAGLEN_MAX];
    uint8_t *ptr = tlbuf;

    json_io_t elem;

    if( !XfmtJson_LintObject(jstr) )
        return -1;

    accum = 0;

    //
    // OtherPrimeInfo ::= SEQUENCE {

    //
    // prime INTEGER, -- r_i
    elem = XfmtJson_ScanObjectForKey(jstr, "r");
    if( !~elem.offset ) return -1;
    subret = BERIntegerFromBase64URL(
        elem, DeltaAdd(enc, accum), enclen - accum);
    if( subret < 0 ) return -1;
    accum += subret;

    //
    // prime INTEGER, -- d_i
    elem = XfmtJson_ScanObjectForKey(jstr, "d");
    if( !~elem.offset ) return -1;
    subret = BERIntegerFromBase64URL(
        elem, DeltaAdd(enc, accum), enclen - accum);
    if( subret < 0 ) return -1;
    accum += subret;

    //
    // prime INTEGER, -- t_i
    elem = XfmtJson_ScanObjectForKey(jstr, "t");
    if( !~elem.offset ) return -1;
    subret = BERIntegerFromBase64URL(
        elem, DeltaAdd(enc, accum), enclen - accum);
    if( subret < 0 ) return -1;
    accum += subret;

    //
    // } -- End of "OtherPrimeInfo ::= SEQUENCE"

    ptr += ber_put_tag(ptr, BER_TLV_TAG_UNI(16), 1);
    ptr += ber_put_len(ptr, accum);
    subret = ptr - tlbuf;

    if( enc )
    {
        IntPtr t;
        if( accum + subret > (IntPtr)enclen )
            return -1;

        for(t=accum+subret; t-->subret; )
            enc[t] = enc[t - subret];

        for(t=subret; t-->0; )
            enc[t] = tlbuf[t];
    }

    return accum + subret;
}

static IntPtr OtherPrimeInfos_FromJsonArray(
    json_io_t jstr, uint8_t *enc, size_t enclen)
{
    IntPtr subret, accum;
    IntPtr t;
    uint8_t tlbuf[TAGLEN_MAX];
    uint8_t *ptr = tlbuf;

    json_io_t elem;

    accum = 0;

    //
    // OtherPrimeInfos ::= SEQUENCE OF OtherPrimeInfo

    t = 0;
    while( true )
    {
        elem = XfmtJson_FindIndexInArray(jstr, t);
        if( !~elem.offset ) break;

        subret = OtherPrimeInfo_FromJsonObject(
            elem, DeltaAdd(enc, accum), enclen - accum);
        if( subret < 0 ) return -1;
        accum += subret;

        t++;
    }

    ptr += ber_put_tag(ptr, BER_TLV_TAG_UNI(16), 1);
    ptr += ber_put_len(ptr, accum);
    subret = ptr - tlbuf;

    if( enc )
    {
        if( accum + subret > (IntPtr)enclen )
            return -1;

        for(t=accum+subret; t-->subret; )
            enc[t] = enc[t - subret];

        for(t=subret; t-->0; )
            enc[t] = tlbuf[t];
    }

    return accum + subret;
}

IntPtr RSAPrivateKey_FromJWK(
    json_io_t jstr, uint8_t *enc, size_t enclen)
{
    IntPtr ret, subret;
    uint8_t tlbuf[TAGLEN_MAX];
    uint8_t *ptr = tlbuf;
    IntPtr t;

    json_io_t elem;
    VLONG_T(1) ver;

    if( !XfmtJson_LintObject(jstr) )
        return -1;

    ret = 0;
    ver.c = 1;

    if( ~XfmtJson_ScanObjectForKey(jstr, "oth").offset )
        ver.v[0] = 1;
    else ver.v[0] = 0;

    //
    // RSAPrivateKey ::= SEQUENCE {

    //
    // version Version, -- Version ::= INTEGER ( two-prime(0), multi(1) ) --
    subret = ber_tlv_put_integer(&ver, DeltaAdd(enc, ret), enclen-ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // modulus INTEGER, -- n
    elem = XfmtJson_ScanObjectForKey(jstr, "n");
    if( !~elem.offset ) return -1;
    subret = BERIntegerFromBase64URL(
        elem, DeltaAdd(enc, ret), enclen - ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // publicExponent INTEGER, -- e
    elem = XfmtJson_ScanObjectForKey(jstr, "e");
    if( !~elem.offset ) return -1;
    subret = BERIntegerFromBase64URL(
        elem, DeltaAdd(enc, ret), enclen - ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // privateExponent INTEGER, -- d
    elem = XfmtJson_ScanObjectForKey(jstr, "d");
    if( !~elem.offset ) return -1;
    subret = BERIntegerFromBase64URL(
        elem, DeltaAdd(enc, ret), enclen - ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // prime1 INTEGER, -- p
    elem = XfmtJson_ScanObjectForKey(jstr, "p");
    if( !~elem.offset ) return -1;
    subret = BERIntegerFromBase64URL(
        elem, DeltaAdd(enc, ret), enclen - ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // prime2 INTEGER, -- q
    elem = XfmtJson_ScanObjectForKey(jstr, "q");
    if( !~elem.offset ) return -1;
    subret = BERIntegerFromBase64URL(
        elem, DeltaAdd(enc, ret), enclen - ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // exponent1 INTEGER, -- d mod (p-1)
    elem = XfmtJson_ScanObjectForKey(jstr, "dp");
    if( !~elem.offset ) return -1;
    subret = BERIntegerFromBase64URL(
        elem, DeltaAdd(enc, ret), enclen - ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // exponent2 INTEGER, -- d mod (q-1)
    elem = XfmtJson_ScanObjectForKey(jstr, "dq");
    if( !~elem.offset ) return -1;
    subret = BERIntegerFromBase64URL(
        elem, DeltaAdd(enc, ret), enclen - ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // coefficient INTEGER, -- (inverse of q) mod p
    elem = XfmtJson_ScanObjectForKey(jstr, "qi");
    if( !~elem.offset ) return -1;
    subret = BERIntegerFromBase64URL(
        elem, DeltaAdd(enc, ret), enclen - ret);
    if( subret < 0 ) return -1;
    ret += subret;

    if( ver.v[0] == 0 )
    {
        // has nothing to do.
    }
    else if( ver.v[0] == 1 )
    {
        //
        // otherPrimeInfos OtherPrimeInfos OPTIONAL
        // -- OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo --

        elem = XfmtJson_ScanObjectForKey(jstr, "oth");
        if( !~elem.offset ) return -1;

        subret = OtherPrimeInfos_FromJsonArray(
            elem, DeltaAdd(enc, ret), enclen - ret);
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
