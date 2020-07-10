/* DannyNiu/NJF, 2018-02-16. Public Domain. */

#include "../0-datum/endian.h"
#include "chacha.h"

static const uint8_t sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

// char:    8-bit,
// short:   16-bit,
// word:    32-bit,
// long;    64-bit. 

#define qround(a, b, c, d)                      \
    {                                           \
        a += b; d ^= a; d = (d<<16)|(d>>16);    \
        c += d; b ^= c; b = (b<<12)|(b>>20);    \
        a += b; d ^= a; d = (d<< 8)|(d>>24);    \
        c += d; b ^= c; b = (b<< 7)|(b>>25);    \
    }

#define qround_word(a, b, c, d, x, y)                           \
    {                                                           \
        a += b + le32toh(x); d ^= a; d = (d>>16)|(d<<16);       \
        c += d             ; b ^= c; b = (b>>12)|(b<<20);       \
        a += b + le32toh(y); d ^= a; d = (d>> 8)|(d<<24);       \
        c += d             ; b ^= c; b = (b>> 7)|(b<<25);       \
    }

#define qround_long(a, b, c, d, x, y)                           \
    {                                                           \
        a += b + le64toh(x); d ^= a; d = (d>>32)|(d<<32);       \
        c += d             ; b ^= c; b = (b>>24)|(b<<40);       \
        a += b + le64toh(y); d ^= a; d = (d>>16)|(d<<48);       \
        c += d             ; b ^= c; b = (b>>63)|(b<< 1);       \
    }

#define msg(i) ( m ? m[s[i]] : 0 )

static inline void
inner_block(uint32_t state[16])
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

static inline void
inner_block_word(uint32_t state[16], uint32_t const m[16], uint8_t const s[16])
{
    qround_word(state[ 0], state[ 4], state[ 8], state[12], msg( 0), msg( 1));
    qround_word(state[ 1], state[ 5], state[ 9], state[13], msg( 2), msg( 3));
    qround_word(state[ 2], state[ 6], state[10], state[14], msg( 4), msg( 5));
    qround_word(state[ 3], state[ 7], state[11], state[15], msg( 6), msg( 7));
    
    qround_word(state[ 0], state[ 5], state[10], state[15], msg( 8), msg( 9));
    qround_word(state[ 1], state[ 6], state[11], state[12], msg(10), msg(11));
    qround_word(state[ 2], state[ 7], state[ 8], state[13], msg(12), msg(13));
    qround_word(state[ 3], state[ 4], state[ 9], state[14], msg(14), msg(15));
}

static inline void
inner_block_long(uint64_t state[16], uint64_t const m[16], uint8_t const s[16])
{
    qround_long(state[ 0], state[ 4], state[ 8], state[12], msg( 0), msg( 1));
    qround_long(state[ 1], state[ 5], state[ 9], state[13], msg( 2), msg( 3));
    qround_long(state[ 2], state[ 6], state[10], state[14], msg( 4), msg( 5));
    qround_long(state[ 3], state[ 7], state[11], state[15], msg( 6), msg( 7));
    
    qround_long(state[ 0], state[ 5], state[10], state[15], msg( 8), msg( 9));
    qround_long(state[ 1], state[ 6], state[11], state[12], msg(10), msg(11));
    qround_long(state[ 2], state[ 7], state[ 8], state[13], msg(12), msg(13));
    qround_long(state[ 3], state[ 4], state[ 9], state[14], msg(14), msg(15));
}

void chacha20_set_state(
    void *restrict state,
    void const *restrict key,
    void const *restrict nonce)
{
    uint32_t *s = state;
    int i;
    
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;

    if( key ) {
        for(i=0; i<8; i++)
            s[i+4] = le32toh( ((const uint32_t *)key)[i] );
    }

    if( nonce ) {
        for(i=0; i<3; i++)
            s[i+13] = le32toh( ((const uint32_t *)nonce)[i] );
    }
}

void chacha20_block(
    uint32_t *restrict state,
    uint32_t counter, 
    size_t len, void const *in, void *out)
{
    uint32_t *s = state, ws[16];
    uint8_t *ptr = (void *)ws;
    size_t i;

    s[12] = counter; for(i=0; i<16; i++) { ws[i] = s[i]; }

    for(i=0; i<10; i++) { inner_block(ws); }

    for(i=0; i<16; i++) { ws[i] = htole32( ws[i] + s[i] ); }

    if( out )
    {
        for(i=0; i<len; i++)
        {
            ((uint8_t *)out)[i] = ptr[i] ^
                (in ? ((const uint8_t *)in)[i] : 0);
        }
    }
}

void blake2s_compress(uint32_t *restrict h, void const *m, uint64_t t, int f)
{
    int i;
    uint32_t v[16];
    
    for(i=0; i<8; i++) v[i] = h[i];
    v[ 8] = 0x6a09e667;
    v[ 9] = 0xbb67ae85;
    v[10] = 0x3c6ef372;
    v[11] = 0xa54ff53a;
    v[12] = 0x510e527f;
    v[13] = 0x9b05688c;
    v[14] = 0x1f83d9ab;
    v[15] = 0x5be0cd19;

    v[12] ^= t;
    v[13] ^= t>>32;

    if( f ) v[14] = ~v[14];

    for(i=0; i<10; i++)
        inner_block_word(v, m, sigma[i%10]);

    for(i=0; i<8; i++)
        h[i] ^= v[i] ^ v[i+8];
}

void blake2b_compress(uint64_t *restrict h, void const *m, uint64_t t, int f)
{
    int i;
    uint64_t v[16];
    
    for(i=0; i<8; i++) v[i] = h[i];
    v[ 8] = 0x6a09e667f3bcc908;
    v[ 9] = 0xbb67ae8584caa73b;
    v[10] = 0x3c6ef372fe94f82b;
    v[11] = 0xa54ff53a5f1d36f1;
    v[12] = 0x510e527fade682d1;
    v[13] = 0x9b05688c2b3e6c1f;
    v[14] = 0x1f83d9abfb41bd6b;
    v[15] = 0x5be0cd19137e2179;

    v[12] ^= t;
    // Not implemented for msglen > 2^64. 

    if( f ) v[14] = ~v[14];

    for(i=0; i<12; i++)
        inner_block_long(v, m, sigma[i%10]);

    for(i=0; i<8; i++)
        h[i] ^= v[i] ^ v[i+8];
}
