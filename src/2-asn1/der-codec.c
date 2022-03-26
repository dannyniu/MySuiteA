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

size_t ber_get_len(const uint8_t **buf, size_t *len)
{
    const uint8_t *p = *buf;
    size_t remain = *len;

    size_t ret = 0, s = 0;

    // see [2021-02-12:presumption-failure].
    
    ret = *p;
    p++; remain--;

    if( ret < 128 ) goto done;

    s = ret & 0x7F;
    if( s > sizeof(size_t) || s > remain )
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
    uint32_t *tag, size_t *len)
{
    if( !~(*tag = ber_get_tag(ptr, remain)) ) return -1;
    if( !~(*len = ber_get_len(ptr, remain)) ) return -1;
    if( *len > *remain ) return -1;
    return 0;
}

size_t ber_push_len(uint8_t **stack, size_t val)
{
    if( val < 0x80 )
    {
        if( *stack )
        {
            *(--(*stack)) = val;
        }
        return 1;
    }
    
    else
    {
        size_t ret = 0;
        while( val )
        {
            if( *stack ) *(--(*stack)) = val;
            val >>= 8;
            ret++;
        }
        
        if( *stack ) *(--(*stack)) = 0x80 | ret;
        return ret + 1;
    }
}

size_t ber_push_tag(uint8_t **stack, uint32_t val, int pc)
{
    uint8_t tagflags = ((6 & (val >> 28)) | (pc & 1)) << 5;
    val &= BER_TLV_TAG_MAX;
    
    if( val < (uint32_t)1 << 5 )
    {
        if( *stack )
        {
            *(--(*stack)) = tagflags | val;
        }
        return 1;
    }

    else if( val < (uint32_t)1 << (7 * 1) )
    {
        if( *stack )
        {
            *(--(*stack)) = val;
            *(--(*stack)) = tagflags | 31;
        }
        return 2;
    }

    else if( val < (uint32_t)1 << (7 * 2) )
    {
        if( *stack )
        {
            *(--(*stack)) = 0x7f & val;
            *(--(*stack)) = (0x7f & (val >>  7)) | 0x80;
            *(--(*stack)) = tagflags | 31;
        }
        return 3;
    }

    else if( val < (uint32_t)1 << (7 * 3) )
    {
        if( *stack )
        {
            *(--(*stack)) = 0x7f & val;
            *(--(*stack)) = (0x7f & (val >>  7)) | 0x80;
            *(--(*stack)) = (0x7f & (val >> 14)) | 0x80;
            *(--(*stack)) = tagflags | 31;
        }
        return 4;
    }

    else if( val < (uint32_t)1 << (7 * 4) )
    {
        if( *stack )
        {
            *(--(*stack)) = 0x7f & val;
            *(--(*stack)) = (0x7f & (val >>  7)) | 0x80;
            *(--(*stack)) = (0x7f & (val >> 14)) | 0x80;
            *(--(*stack)) = (0x7f & (val >> 21)) | 0x80;
            *(--(*stack)) = tagflags | 31;
        }
        return 5;
    }

    else return 0;
}

void *ber_util_splice_insert(
    void *buf,        size_t len1,
    ptrdiff_t offset, size_t len2)
{
    // Moves base[0:len1] to base[len2:len1+len2] and
    // then base[offset:offset+len2] to base[0:len2]
    // in such way that the contents of both segments are preserved.
    //
    // Assumption:
    // 1. offset is finitely positive,
    // 2. len1 <= offset, and
    // 3. len1 > 0.
    //
    // Returns buf.

    uint8_t *base, *src, *dst, *swap, save;
    size_t copy_remain, i;

    base = buf;

    if( !len1 )
    {
        for(i=0; i<len2; i++)
            base[i] = base[i + offset];

        return buf; // Edge case handled specially.
    }

    // == iteration starts ==
loop:
    src = (uint8_t *)buf + offset;
    dst = base;
    swap = base + len1;

    // == copying start ==
    copy_remain = len1 < len2 ? len1 : len2;
    if( !copy_remain ) return buf;

    for(i=0; i<copy_remain; i++)
    {
        save    = src[i];
        swap[i] = dst[i];
        dst[i]  = save;
    }
    // == copying puases ==

    if( len1 > len2 )
    {
        // next source segment:
        // current source segment is exhausted,
        // use ``swap'' in the next iteration;
        offset = len1 + (size_t)(base - (uint8_t *)buf);
        len2 = copy_remain;

        // next destination segment:
        // the remain following one.
        base += copy_remain;
        len1 -= copy_remain;
    }
    
    else // len1 <= len2.
    {
        // next source segment:
        // only part of ``src'' had been copied, copy the
        // next part(s) in the next iteration.
        offset += copy_remain;
        len2 -= copy_remain;

        // next destination segment:
        // current destination is exhausted,
        // use ``swap'' in the next iteration.
        base += copy_remain;
        len1 = copy_remain;
    }

    goto loop;
}

IntPtr ber_tlv_decode_integer(BER_TLV_DECODING_FUNC_PARAMS)
{
    // [ber-int-err-chk:2021-02-13]:
    // Because this function has no failure return values (yet),
    // caller may skip checking error for this function (for now).

    // 2022-02-13: changed to use the macro fron "vlong.h".
    IntPtr ret = VLONG_BYTES_SIZE(enclen);
    
    vlong_t *w = any;
    uint32_t i;
    
    if( !any ) return ret;

    w->c = VLONG_BYTES_WCNT(enclen);
    
    for(i=0; i<w->c; i++) w->v[i] = 0;

    for(i=0; i<enclen; i++)
    {
        w->v[i / sizeof(uint32_t)] |=
            (uint32_t)enc[enclen - i - 1] << ((i % sizeof(uint32_t)) * 8);
    }

    return ret;
}

IntPtr ber_tlv_encode_integer(BER_TLV_ENCODING_FUNC_PARAMS)
{
    // 2021-04-17: This function had not been tested yet.

    // [ber-int-err-chk:2021-02-13].

    size_t ret = 0;
    size_t i;
    const vlong_t *w = any;

    // silence 2 unused variable warnings.
    (void)enclen;

    // This function handles only unsigned integers.
    ret = w->c * sizeof(uint32_t) + 1;
    for(i=w->c; --i < w->c; )
    {
        if( w->v[i] < UINT32_C(1) << 31 ) ret--;
        if( w->v[i] < UINT32_C(1) << 23 ) ret--;
        if( w->v[i] < UINT32_C(1) << 15 ) ret--;
        if( w->v[i] < UINT32_C(1) <<  7 ) ret--;
        if( w->v[i] ) break;
    }

    if( !enc ) return ret;

    for(i=0; i<ret; i++) // i is the byte position in enc,
    {
        uint32_t u, v; // v is the shift amount,
        u = ret - i - 1;
        v = (u % sizeof(uint32_t)) * 8;
        u /= sizeof(uint32_t); // u is the position in vlong.
        enc[i] = u < w->c ? (w->v[u] >> v) : 0;
    }

    return ret;
}
