/* DannyNiu/NJF, 2018-04-10. Public Domain. */

#include "../mysuitea-common.h"
#include "../1-asymm/bignum.h"

#define nextbyte (                                                      \
        ( buf - (const uint8_t *)der < bufferlen ) ? *buf++ : -1        \
        )

const void *asn1_decode_length(signed long *out, const void *restrict der, size_t bufferlen)
{
    const uint8_t *buf = der;
    int c, t;
    signed long ret;
    
    if( (c = nextbyte) == -1 ) return NULL;

    if( c < 128 ) {
        *out = c;
        return buf;
    } else {
        t = c & 127;
        ret = 0;
        while( t-- ) {
            if( (c = nextbyte) == -1 ) return NULL;
            ret = (ret << 8) | c;
        }
        *out = ret;
        return buf;
    }
}

const void *asn1_decode_integer(long n, bn_t *restrict bn, const void *restrict der, size_t bufferlen)
{
    const uint8_t *buf = der, *nested;
    int c, i;
    signed long len;

    // fetch initial octet. 
    if( (c = nextbyte) == -1 ) return NULL;

    // identifier octet(s). TODO? add case for context-specific class? 
    if( c != 0x02 ) return NULL;

    // length octets. 
    nested = asn1_decode_length(&len, buf, (const uint8_t *)der + bufferlen - buf);
    if( !nested ) return NULL;
    else buf = nested;

    // checking length. 
    if( len > sizeof(bn->w[0]) * n ) return NULL;
    if( len > (const uint8_t *)der + bufferlen - buf ) return NULL;

    // initialize bn. 
    for(i=0; i<n; i++) {
        bn->w[i] = 0;
    }

    // fill bn with content octets. 
    while( len-- && (c = nextbyte) >= 0 ) { // Must check length before ''nextbyte''. 
        bn->w[len / sizeof(bn->w[0])] |= c << ((len % sizeof(bn->w[0])) * 8);
    }

    // finishing. 
    if( ++len ) return NULL; // shouldn't happen.
    else return buf;
}
