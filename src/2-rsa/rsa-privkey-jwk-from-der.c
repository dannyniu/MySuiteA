/* DannyNiu/NJF, 2025-06-30. Public Domain. */

#include "../2-pkc-xfmt/pkc-xfmt.h"
#include "../2-asn1/der-codec.h"
#include "../0-exec/struct-delta.c.h"

#define BER_HDR ber_get_hdr(&ptr, &remain, &tag, &len)

static json_io_t *OtherPrimeInfo_FromDER(
    json_io_t *jctx, const uint8_t *enc, size_t enclen)
{
    json_io_t *ret = jctx;

    const uint8_t *ptr = enc;
    size_t remain = enclen;

    uint32_t tag;
    size_t len;

    //
    // OtherPrimeInfo ::= SEQUENCE {
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(16) ) return NULL;
    ret = json_putc(jctx, '{');

    //
    // prime INTEGER, -- r_i
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(2) ) return NULL;
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, 'r');
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ':');

    ret = json_putc(jctx, '"');
    ret = UIntBase64URLTrimOctetString(jctx, ptr, len);
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ',');
    ptr += len; remain -= len;

    //
    // prime INTEGER, -- d_i
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(2) ) return NULL;
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, 'd');
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ':');

    ret = json_putc(jctx, '"');
    ret = UIntBase64URLTrimOctetString(jctx, ptr, len);
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ',');
    ptr += len; remain -= len;

    //
    // prime INTEGER, -- t_i
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(2) ) return NULL;
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, 't');
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ':');

    ret = json_putc(jctx, '"');
    ret = UIntBase64URLTrimOctetString(jctx, ptr, len);
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, '}');
    ptr += len; remain -= len;

    //
    // } -- End of "OtherPrimeInfo ::= SEQUENCE"

    jctx->info = enclen - remain;
    return ret;
}

int printf(const char *, ...);
#define eprintf printf
void dumphex(void *, size_t );

static json_io_t *OtherPrimeInfos_FromDER(
    json_io_t *jctx, const uint8_t *enc, size_t enclen)
{
    json_io_t *ret = jctx;

    const uint8_t *ptr = enc;
    size_t remain = enclen;

    uint32_t tag;
    size_t len;

    int sep = '[';

    //
    // OtherPrimeInfos ::= SEQUENCE OF OtherPrimeInfo
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(16) ) return NULL;

    while( remain )
    {
        if( !(ret = json_putc(jctx, sep)) ) return NULL;
        sep = ',';
        if( !(ret = OtherPrimeInfo_FromDER(jctx, ptr, len)) ) return NULL;
        ptr += jctx->info; remain -= jctx->info;
    }
    ret = json_putc(jctx, ']');

    jctx->info = enclen - remain;
    return ret;
}

json_io_t *RSAPrivateKey_ToJWK(
    json_io_t *jctx, const uint8_t *enc, size_t enclen)
{
    json_io_t *ret = jctx;

    const uint8_t *ptr = enc;
    size_t remain = enclen;

    uint32_t tag;
    size_t len;

    size_t t;
    uint32_t version;

    //
    // RSAPrivateKey ::= SEQUENCE {
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(16) ) return NULL;
    ret = json_putc(jctx, '{');

    //
    // version Version, -- Version ::= INTEGER ( two-prime(0), multi(1) ) --
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(2) ) return NULL;

    for(t=0, version = 0; t<len; t++) version = (version << 8) | ptr[t];
    ptr += len; remain -= len;

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
    ret = json_putc(jctx, ',');
    ptr += len; remain -= len;

    //
    // privateExponent INTEGER, -- d
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(2) ) return NULL;
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, 'd');
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ':');

    ret = json_putc(jctx, '"');
    ret = UIntBase64URLTrimOctetString(jctx, ptr, len);
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ',');
    ptr += len; remain -= len;

    //
    // prime1 INTEGER, -- p
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(2) ) return NULL;
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, 'p');
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ':');

    ret = json_putc(jctx, '"');
    ret = UIntBase64URLTrimOctetString(jctx, ptr, len);
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ',');
    ptr += len; remain -= len;

    //
    // prime2 INTEGER, -- q
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(2) ) return NULL;
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, 'q');
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ':');

    ret = json_putc(jctx, '"');
    ret = UIntBase64URLTrimOctetString(jctx, ptr, len);
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ',');
    ptr += len; remain -= len;

    //
    // exponent1 INTEGER, -- d mod (p-1)
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(2) ) return NULL;
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, 'd');
    ret = json_putc(jctx, 'p');
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ':');

    ret = json_putc(jctx, '"');
    ret = UIntBase64URLTrimOctetString(jctx, ptr, len);
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ',');
    ptr += len; remain -= len;

    //
    // exponent2 INTEGER, -- d mod (q-1)
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(2) ) return NULL;
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, 'd');
    ret = json_putc(jctx, 'q');
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ':');

    ret = json_putc(jctx, '"');
    ret = UIntBase64URLTrimOctetString(jctx, ptr, len);
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ',');
    ptr += len; remain -= len;

    //
    // coefficient INTEGER, -- (inverse of q) mod p
    if( -1 == BER_HDR ) return NULL;
    if( tag != BER_TLV_TAG_UNI(2) ) return NULL;
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, 'q');
    ret = json_putc(jctx, 'i');
    ret = json_putc(jctx, '"');
    ret = json_putc(jctx, ':');

    ret = json_putc(jctx, '"');
    ret = UIntBase64URLTrimOctetString(jctx, ptr, len);
    ret = json_putc(jctx, '"');
    ptr += len; remain -= len;

    if( version == 0 )
    {
        ret = json_putc(jctx, '}');
    }
    else if( version == 1 )
    {
        ret = json_putc(jctx, ',');
        ret = json_putc(jctx, '"');
        ret = json_putc(jctx, 'o');
        ret = json_putc(jctx, 't');
        ret = json_putc(jctx, 'h');
        ret = json_putc(jctx, '"');
        ret = json_putc(jctx, ':');
        ret = OtherPrimeInfos_FromDER(jctx, ptr, remain);
        ret = json_putc(jctx, '}');
        ptr += jctx->info; remain -= jctx->info;
    }

    jctx->info = enclen - remain;
    return ret;
}
