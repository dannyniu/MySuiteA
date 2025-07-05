/* DannyNiu/NJF, 2025-07-05. Public Domain. */

#include "rsa-codec-jwk.h"
#include "../2-asn1/der-codec.h"
#include "../0-exec/struct-delta.c.h"

#define BER_HDR ber_get_hdr(&ptr, &remain, &tag, &len)

json_io_t *RSAPublicKey_ToJWK(
    json_io_t *jctx, const uint8_t *enc, size_t enclen)
{
    json_io_t *ret = jctx;

    const uint8_t *ptr = enc;
    size_t remain = enclen;

    uint32_t tag;
    size_t len;
    size_t t;

    //
    // RSAPublicKey ::= SEQUENCE {
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(16) ) return NULL;
    ret = json_putc(jctx, '{');

    for(t=0; t<12; t++) ret = json_putc(jctx, ("\"kty\":\"RSA\",")[t]);

    //
    // modulus INTEGER, -- n
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(2) ) return NULL;
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, 'n');
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ':');

    ret = json_putc(jctx, '"');
    ret = UIntBase64URLTrimOctetString(jctx, ptr, len);
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ',');
    ptr += len; remain -= len;

    //
    // publicExponent INTEGER, -- e
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(2) ) return NULL;
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, 'e');
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ':');

    ret = json_putc(jctx, '"');
    ret = UIntBase64URLTrimOctetString(jctx, ptr, len);
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, '}');
    ptr += len; remain -= len;

    //
    // } -- End of "RSAPublicKey ::= SEQUENCE"

    jctx->info = enclen - remain;
    return ret;
}

IntPtr RSAPublicKey_FromJWK(
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
    // RSAPublicKey ::= SEQUENCE {

    //
    // modulus INTEGER, -- n
    elem = XfmtJson_ScanObjectForKey(jstr, "n");
    if( !~elem.offset ) return -1;
    subret = BERIntegerFromBase64URL(
        elem, DeltaAdd(enc, accum), enclen - accum);
    if( subret < 0 ) return -1;
    accum += subret;

    //
    // publicExponent INTEGER, -- e
    elem = XfmtJson_ScanObjectForKey(jstr, "e");
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
