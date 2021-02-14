/* DannyNiu/NJF, 2021-02-12. Public Domain. */

#include "der-codec.h"

uint32_t ber_get_tag(const uint8_t **buf, size_t *len)
{
    const uint8_t *p = *buf;
    size_t remain = *len;

    uint32_t tag = 0;
    uint32_t cls;

    // [2021-02-12:presumption-failure]:
    // may have to check ``remain'' at this point.
    // but assuming len >= 1 for now.
    
    cls = *p >> 6;
    tag = *p & 31;
    p++; remain--;

    if( tag < 31 )
    {
        tag |= 0x80000000 | cls << 29;
        goto done;
    }

    tag = 0;

    while( remain && p - *buf < 4 ) // support tag values up to only 28 bits.
    {
        remain--;
        tag <<= 7;
        tag |= *p & 0x7F;
        
        if( !(*p++ & 0x80) )
        {
            tag |= 0x80000000 | cls << 29;
            goto done;
        }
    }

    tag = -1;

done:
    *buf = p; *len = remain;
    return tag;
}

uint32_t ber_get_len(const uint8_t **buf, size_t *len)
{
    const uint8_t *p = *buf;
    size_t remain = *len;

    uint32_t ret = 0, s = 0;

    // see [2021-02-12:presumption-failure].
    
    ret = *p;
    p++; remain--;

    if( ret < 128 ) goto done;

    s = ret & 0x7F;
    if( s > 4 || s > remain )
    {
        // Actually, I wanted to handle the case where (*buf)[0] is 0xff
        // as X.690 reserves it for future extension, but my case is
        // much simpler here.
        ret = -1;
        goto done;
    }

    ret = 0;

    while( s-- )
    {
        ret = ret << 8 | *p;
        p++; remain--;
    }

done:
    *buf = p; *len = remain;
    return ret;
}

int ber_get_hdr(
    const uint8_t **ptr, size_t *remain,
    uint32_t *tag, uint32_t *len)
{
    if( !~(*tag = ber_get_tag(ptr, remain)) ) return -1;
    if( !~(*len = ber_get_len(ptr, remain)) ) return -1;
    if( *len > *remain ) return -1;
    return 0;
}

int32_t ber_tlv_decode_integer(BER_TLV_DECODING_FUNC_PARAMS)
{
    // [ber-int-err-chk:2021-02-13]:
    // Because this function has no failure return values (yet),
    // caller may skip checking error for this function.
    
    int32_t ret =
        (srclen + sizeof(uint32_t) * 2 - 1) &
        (uint32_t)(-sizeof(uint32_t));
    vlong_t *w = dst;
    uint32_t i;
    aux = NULL; // silence the unused parameter warning.

    if( pass == 1 ) return ret;

    w->c = (srclen + sizeof(uint32_t) - 1) / sizeof(uint32_t);
    for(i=0; i<w->c; i++) w->v[i] = 0;

    for(i=0; i<srclen; i++)
    {
        w->v[i / sizeof(uint32_t)] |=
            src[srclen - i - 1] << ((i % sizeof(uint32_t)) * 8);
    }

    return ret;
}
