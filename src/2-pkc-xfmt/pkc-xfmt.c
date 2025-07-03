/* DannyNiu/NJF, 2025-06-15. Public Domain. */

#include "pkc-xfmt.h"
#include "../2-asn1/der-codec.h"

static_assert( ' ' == 0x20 && '0' == 0x30 && 'A' == 0x41 ,
               "ASCII or compatible character set required!" );

static int atob(int letter)
{
    if( 'A' <= letter && letter <= 'Z' ) return 0  + letter - 'A';
    if( 'a' <= letter && letter <= 'z' ) return 26 + letter - 'a';
    if( '0' <= letter && letter <= '9' ) return 52 + letter - '0';
    if( letter == '-' ) return 62;
    if( letter == '_' ) return 63;
    return -1;
}

static int btoa(int value)
{
    if( 0  <= value && value <= 25 ) return 'A' + value - 0;
    if( 26 <= value && value <= 51 ) return 'a' + value - 26;
    if( 52 <= value && value <= 61 ) return '0' + value - 52;
    if( value == 62 ) return '-';
    if( value == 63 ) return '_';
    return -1;
}

int XfmtReadByteFromBase64URL(
    const void *restrict src, size_t srclen,
    pkc_xfmt_accel_t *restrict accel,
    int32_t component, int32_t position,
    CryptoParam_t *restrict algoparams)
{
    uint32_t base =  (uint32_t)accel->position / 16;
    uint32_t clen = ((uint32_t)accel->position % 16) % 5;
    uint32_t encs = ((uint32_t)accel->position % 16) / 5;
    uint32_t t;
    uint8_t const *ptr = src;
    int dec = 0, filled = 0;

    (void)component;
    (void)algoparams;
    ptr += accel->offset;

    while( (uint32_t)position - base >= clen ) // update cache.
    {
        if( clen < 3 && encs == 2 ) return -1; // EOF.

        t = base = position - position % 3;
        t = t * 4 / 3;

        for(accel->position = 0; t < srclen && accel->position < 3; )
        {
            int b = atob(ptr[t++]);
            if( b == -1 ) break;
            dec = (dec << 6) | b;
            filled += 6;
            while( filled >= 8 )
                accel->cache[accel->position++] =
                    dec >> (filled -= 8);
        }

        clen = accel->position;
        encs = 2;
        accel->position += (position - position % 3) * 16 + encs * 5;
    }

    return accel->cache[position - base];
}

#define BER_HDR ber_get_hdr(&ptr, &remain, &tag, &len)

int XfmtReadByteFromBERInteger(
    const void *restrict src, size_t srclen,
    pkc_xfmt_accel_t *restrict accel,
    int32_t component, int32_t position,
    CryptoParam_t *restrict algoparams)
{
    const uint8_t *ptr = src;
    size_t remain = srclen;
    uint32_t tag;
    size_t len;

    uint32_t base =  (uint32_t)accel->position / 16;
    uint32_t clen = ((uint32_t)accel->position % 16) % 5;
    uint32_t encs = ((uint32_t)accel->position % 16) / 5;
    uint32_t t;

    (void)component;
    (void)algoparams;

    while( (uint32_t)position - base >= clen ) // update cache.
    {
        if( clen < 4 && accel->offset > 0 ) return -1; // EOF.

        t = base = position - position % 4;

        //- if( accel->offset == 0 ) // need to unconditionally compute `len`,
        if( -1 == BER_HDR ) return -1;
        if( tag != BER_TLV_TAG_UNI(2) ) return -1;
        accel->offset = srclen - remain;
        //- end-if;
        // 2025-06-23:
        // Consider specify `position % 16 == 15` as meaning p equals `len`.

        for(accel->position = 0; t < len && accel->position < 4; )
        {
            accel->cache[accel->position++] =
                ((const uint8_t *)src)[accel->offset + t++];
        }

        clen = accel->position;
        encs = 0;
        accel->position += (position - position % 4) * 16 + encs * 5;
    }

    return accel->cache[position - base];
}

#define JSON_GETC json_getc(&JsonValue)
#define JSON_PEEK json_peek(&JsonValue)
#define JSON_INCR json_incr(&JsonValue)

// JSON Read-EOF.
// `.offset` is set to equivalent to SIZE_MAX.
#define JSON_REOF ((json_io_t){                 \
            .str = JsonValue.str,               \
            .limit = JsonValue.limit,           \
            .offset = (size_t)-1,               \
            .info = -1 })

json_io_t XfmtJson_Skip1Value(json_io_t JsonValue)
{
    JsonValue = XfmtJson_SkipWhitespace(JsonValue);
    ;;;; if( JSON_PEEK == '[' ) JsonValue = XfmtJson_Skip1Array(JsonValue);
    else if( JSON_PEEK == '{' ) JsonValue = XfmtJson_Skip1Object(JsonValue);
    else if( JSON_PEEK == '"' ) JsonValue = XfmtJson_Skip1String(JsonValue);
    else {
        // Skip 1 Primitive Value.
        int i;
        static const char primitive[] =
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789+-.\0";
        for(i=0; primitive[i]; i++)
        {
            if( JSON_PEEK < 0 ) return JSON_REOF;
            if( JSON_PEEK == primitive[i] )
                i=0, JSON_INCR;
        }
    }
    JsonValue = XfmtJson_SkipWhitespace(JsonValue);
    return JsonValue;
}

json_io_t XfmtJson_FindIndexInArray(json_io_t JsonValue, long index)
{
    JsonValue = XfmtJson_SkipWhitespace(JsonValue);
    if( JSON_GETC != '[' ) return JSON_REOF;

    while( JSON_PEEK != ']' && index != 0 )
    {
        JsonValue = XfmtJson_Skip1Value(JsonValue);
        if( JSON_PEEK == ']' ) { JSON_INCR; break; }
        if( JSON_PEEK != ',' ) return JSON_REOF;

        JSON_INCR;
        if( index > 0 )
            index --;
        continue;
    }

    if( index > 0 ) return JSON_REOF;
    JsonValue = XfmtJson_SkipWhitespace(JsonValue);
    return JsonValue;
}

json_io_t XfmtJson_ScanObjectForKey(json_io_t JsonValue, const byte *key)
{
    JsonValue = XfmtJson_SkipWhitespace(JsonValue);
    if( JSON_GETC != '{' ) return JSON_REOF;

    while( JSON_PEEK != '}' )
    {
        int res = 0;
        if( key ) res = JsonStringSameWithCString(JsonValue, key);
        if( res < 0 ) return JSON_REOF;

        JsonValue = XfmtJson_Skip1String(JsonValue);
        if( JSON_GETC != ':' ) return JSON_REOF;

        if( res ) return JsonValue;
        JsonValue = XfmtJson_Skip1Value(JsonValue);

        if( JSON_PEEK == '}' ) { JSON_INCR; break; }
        if( JSON_PEEK != ',' ) return JSON_REOF;
        JSON_INCR;
        continue;
    }
    JsonValue = XfmtJson_SkipWhitespace(JsonValue);
    return JsonValue;
}

json_io_t XfmtJson_FindStringEnd(json_io_t JsonValue)
{
    JsonValue = XfmtJson_SkipWhitespace(JsonValue);
    if( JSON_GETC != '"' ) return JSON_REOF;

    while( JSON_PEEK != '"' )
    {
        if( JSON_PEEK < 0 ) return JSON_REOF;
        if( JSON_PEEK == '\\' )
            JSON_INCR, JSON_INCR;
        else JSON_INCR;
    }

    JSON_INCR;
    return JsonValue;
}

json_io_t XfmtJson_Skip1String(json_io_t JsonValue)
{
    JsonValue = XfmtJson_SkipWhitespace(
        XfmtJson_FindStringEnd(JsonValue));
    return JsonValue;
}

json_io_t XfmtJson_SkipWhitespace(json_io_t JsonValue)
{
    while( JSON_PEEK == '\n' || JSON_PEEK == '\r' ||
           JSON_PEEK == '\t' || JSON_PEEK == ' ' ) JSON_INCR;
    return JsonValue;
}

int JsonStringSameWithCString(json_io_t JsonValue, const byte *cstr)
{
    JsonValue = XfmtJson_SkipWhitespace(JsonValue);
    if( JSON_GETC != '"' ) return -1;
    while( JSON_PEEK != '"' )
    {
        if( JSON_PEEK < 0 ) return -1;
        if( JSON_PEEK == '\\' )
        {
            JSON_INCR;
            switch( JSON_PEEK ) {
            case 'b': if( *cstr != '\b' ) return 0; break;
            case 'f': if( *cstr != '\f' ) return 0; break;
            case 'n': if( *cstr != '\n' ) return 0; break;
            case 'r': if( *cstr != '\r' ) return 0; break;
            case 't': if( *cstr != '\t' ) return 0; break;
            default: if( *cstr != JSON_PEEK ) return 0; break; }
            // 2025-06-15:
            // UTF-16 literal require knowledge of character set encoding,
            // as it's not necessary for cryptography, this part is
            // not being implemented.
        }
        else if( JSON_PEEK != *cstr ) return 0;
        JSON_INCR;
        ++ cstr;
    }
    if( *cstr ) return 0;
    return 1;
}

bool XfmtJson_LintObject(json_io_t JsonValue)
{
    // Check for duplicate keys in the object.
    JsonValue = XfmtJson_SkipWhitespace(JsonValue);
    if( JSON_GETC != '{' ) return false;

    while( true )
    {
        size_t k1, e1;
        json_io_t jv;
        JsonValue = XfmtJson_SkipWhitespace(JsonValue);
        k1 = JsonValue.offset;
        JsonValue = XfmtJson_FindStringEnd(JsonValue);
        e1 = JsonValue.offset;

        JsonValue = XfmtJson_SkipWhitespace(JsonValue);
        if( JSON_GETC != ':' ) return false;
        JsonValue = XfmtJson_Skip1Value(JsonValue);

        if( JSON_PEEK == '}' ) break;
        if( JSON_PEEK != ',' ) return false;
        JSON_INCR;

        jv = JsonValue;
        while( true )
        {
            size_t k2, e2;
            jv = XfmtJson_SkipWhitespace(jv);
            k2 = jv.offset;
            jv = XfmtJson_FindStringEnd(jv);
            e2 = jv.offset;
            if( !~k2 || !~e2 ) return false;

            if( e2-k2 == e1-k1 )
            {
                // If the strings match entirely, return false to
                // indicate duplicate keys (i.e. linting failure).
                // If keys don't match exactly (e.g. due to one use
                // escape sequence and the other use raw character)
                // then this may be sign of attack, however, the
                // defined keys in JWT don't have these special characters.
                ptrdiff_t len = e2-k2, i;
                for(i=0; i<len; i++)
                    if( JsonValue.str[k1+i] != JsonValue.str[k2+i] )
                        break;
                if( i == len ) return false;
            }

            jv = XfmtJson_SkipWhitespace(jv);
            if( json_getc(&jv) != ':' ) return false;
            jv = XfmtJson_Skip1Value(jv);

            if( json_peek(&jv) == '}' ) break;
            if( json_peek(&jv) != ',' ) return false;
            json_incr(&jv);
        }
        continue;
    }

    return true;
}

IntPtr BERIntegerFromBase64URL(json_io_t jv, uint8_t *enc, size_t enclen)
{
    pkc_xfmt_accel_t accel = {};
    size_t endquote;
    size_t srclen, t, s, ret, hdr;
    int subret;

    if( !~XfmtJson_Skip1String(jv).offset ) return -1;
    jv = XfmtJson_SkipWhitespace(jv);
    assert( jv.str[jv.offset] == '\"' );

    endquote = XfmtJson_FindStringEnd(jv).offset;
    srclen = endquote - jv.offset - 2;
    jv.offset ++;

    ret = 0, t = 0, s = false;
    while( true )
    {
        subret = XfmtReadByteFromBase64URL(
            jv.str + jv.offset, srclen, &accel, 0, t, NULL);
        if( subret < 0 ) break;
        if( subret || ret ) ret ++;
        if( ret == 1 && (subret & 0x80) ) ret ++;
        t ++;
    }

    hdr =
        ber_put_tag(NULL, BER_TLV_TAG_UNI(2), 0) +
        ber_put_len(NULL, ret);

    if( !enc ) return ret + hdr;
    if( enclen < ret + hdr ) return -1;

    enc += ber_put_tag(enc, BER_TLV_TAG_UNI(2), 0);
    enc += ber_put_len(enc, ret);

    accel = (pkc_xfmt_accel_t){};
    s = t;
    for(t -= ret; ; t++)
    {
        if( t > s ) { *enc++ = 0; continue; }
        subret = XfmtReadByteFromBase64URL(
            jv.str + jv.offset, srclen, &accel, 0, t, NULL);
        if( subret < 0 ) break;
        *enc++ = subret;
    }

    return ret + hdr;
}

json_io_t *json_putc(json_io_t *ctx, int c)
{
    if( !ctx ) return NULL;
    if( ctx->json )
    {
        if( ctx->offset >= ctx->limit ) return NULL;
        ctx->json[ctx->offset] = c;
    }
    ++ ctx->offset;
    return ctx;
}

static inline bool json_read_prelude(json_io_t *ctx)
{
    if( !ctx ) return false;
    if( !ctx->str ) return false;
    if( ctx->offset >= ctx->limit ) return false;
    return true;
}

int json_peek(json_io_t *ctx)
{
    if( !json_read_prelude(ctx) ) return -1;
    return ctx->str[ctx->offset];
}

int json_getc(json_io_t *ctx)
{
    if( !json_read_prelude(ctx) ) return -1;
    return ctx->str[ctx->offset++];
}

void json_incr(json_io_t *ctx)
{
    if( !json_read_prelude(ctx) ) return;
    ctx->offset++;
}

json_io_t *UIntBase64URLCopyOctetString(
    json_io_t *jctx, const uint8_t *src, size_t srclen)
{
    json_io_t *ret = jctx;
    uint32_t w;
    size_t i, j, enclen;

    for(i=0; i<srclen; )
    {
        w = 0;
        for(j=0; j<3 && i<srclen; j++, i++)
            w |= src[i] << (16 - j * 8);

        if( !j ) return ret;
        enclen = j;

        for(j=0; j<=enclen; j++)
        ret = json_putc(jctx, btoa((w >> (18 - j * 6)) & 63));
    }

    return ret;
}

json_io_t *UIntBase64URLTrimOctetString(
    json_io_t *jctx, const uint8_t *src, size_t srclen)
{
    size_t t;

    for(t=0; t<srclen; t++)
    {
        // skip leading nul octets.
        if( src[t] )
            break;
    }

    return UIntBase64URLCopyOctetString(jctx, src+t, srclen-t);
}
