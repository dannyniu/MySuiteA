/* DannyNiu/NJF, 2018-02-16. Public Domain. */

#include "../0-datum/endian.h"
#include "chacha20.h"

#define qround(a, b, c, d)                      \
    {                                           \
        a += b; d ^= a; d = (d<<16)|(d>>16);    \
        c += d; b ^= c; b = (b<<12)|(b>>20);    \
        a += b; d ^= a; d = (d<< 8)|(d>>24);    \
        c += d; b ^= c; b = (b<< 7)|(b>>25);    \
    }

static inline void inner_block(uint32_t state[16])
{
    qround(state[ 0], state[ 4], state[ 8], state[12]);
    qround(state[ 1], state[ 5], state[ 9], state[13]);
    qround(state[ 2], state[ 6], state[10], state[14]);
    qround(state[ 3], state[ 7], state[11], state[15]);
    qround(state[ 0], state[ 5], state[10], state[15]);
    qround(state[ 1], state[ 6], state[11], state[12]);
    qround(state[ 2], state[ 7], state[ 8], state[13]);
    qround(state[ 3], state[ 4], state[ 9], state[14]);
}

void chacha20_set_state(void *restrict state,
                               const void *restrict key,
                               const void *restrict nonce)
{
    uint32_t *s = state;
    int i;
    
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;

    if( key ) {
        for(i=0; i<8; i++)
            s[i+4] = le32toh( ((uint32_t *)key)[i] );
    }

    if( nonce ) {
        for(int i=0; i<3; i++)
            s[i+13] = le32toh( ((uint32_t *)nonce)[i] );
    }
}

void chacha20_block(uint32_t *restrict state, uint32_t counter, 
                           size_t len, const void *in, void *out)
{
    uint32_t *s = state, ws[16];
    uint8_t *ptr = (void *)ws;
    size_t i;

    s[12] = counter; for(i=0; i<16; i++) { ws[i] = s[i]; }

    for(i=0; i<10; i++) { inner_block(ws); }

    for(i=0; i<16; i++) { ws[i] = htole32( ws[i] + s[i] ); }

    for(i=0; i<len; i++) {
        ((uint8_t *)out)[i] = ptr[i] ^
            (in ? ((uint8_t *)in)[i] : 0);
    }
}
