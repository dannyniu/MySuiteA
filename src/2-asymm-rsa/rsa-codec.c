/* DannyNiu/NJF, 2018-04-10. Public Domain. */

#include "rsa-common.h"

// Code template based on interpretation of relevant documents.

#define checklength(len,v)                              \
    do {                                                \
        if( buf - (uint8_t *)der >= (len) ) return v;   \
    } while(0)

#define pushlen                                 \
    *len = *buf++; checklength(len[-1], -1);    \
    if( *len >= 128 ) {                         \
        len[1] = 0;                             \
        while( (*len)-- > 128 ) {               \
            len[1] <<= 8;                       \
            len[1] += *buf++;                   \
            checklength(len[-1], -1);           \
        }                                       \
        *len = len[1];                          \
    }                                           \
    len++;


int rsa_pubkey_decode(rsa_t *restrict ctx, const void *restrict der, size_t bufferlen)
{
    const uint8_t *buf = der;
    size_t lengths[4], *len = &lengths[0];

    // initialize outer-most length variable. 
    *len++ = bufferlen;

    // RSAPublicKey SEQUENCE: identifier octet(s)
    if( *buf++ != 0x30 ) return -1;
    checklength(bufferlen, -1);

    // RSAPublicKey SEQUENCE: length octets
    pushlen;
    
    // RSAPublicKey SEQUENCE: content octets
    // : modulus INTEGER: identifier octet(s)
    if( *buf++ != 0x02 ) return -1;

    // RSAPublicKey SEQUENCE: content octets
    // : modulus INTEGER: length octets
    
}
