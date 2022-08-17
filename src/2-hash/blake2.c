/* DannyNiu/NJF, 2018-12-23. Public Domain. */

#include "blake2.h"
#include "../0-datum/endian.h"

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

static void
blake2s_compress(uint32_t *restrict h, void const *m, uint64_t t, int f)
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

static void
blake2b_compress(uint64_t *restrict h, void const *m, uint64_t t, int f)
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

static void *blake2b_init(
    blake2b_t *restrict x, size_t outlen,
    void const *restrict k, size_t keylen)
{
    size_t i;

    if( outlen > 64 || outlen < 1 || keylen > 64 ) return NULL;

    x->outlen = outlen;
    x->keylen = keylen;
    x->finalized = false;

    x->h[0] = 0x6a09e667f3bcc908;
    x->h[1] = 0xbb67ae8584caa73b;
    x->h[2] = 0x3c6ef372fe94f82b;
    x->h[3] = 0xa54ff53a5f1d36f1;
    x->h[4] = 0x510e527fade682d1;
    x->h[5] = 0x9b05688c2b3e6c1f;
    x->h[6] = 0x1f83d9abfb41bd6b;
    x->h[7] = 0x5be0cd19137e2179;

    x->h[0] ^= UINT32_C(0x01010000) ^ (x->keylen << 8) ^ x->outlen;
    x->t = 0;
    x->filled = 0;

    for(i=0; i<sizeof(x->b); i++) x->b[i] = 0;

    if( keylen > 0 )
    {
        blake2b_update(x, k, keylen);
        x->filled = sizeof(x->b);
    }

    return x;
}

void BLAKE2b160_Init(blake2b_t *restrict x){ blake2b_init(x, 20, NULL, 0); }
void BLAKE2b256_Init(blake2b_t *restrict x){ blake2b_init(x, 32, NULL, 0); }
void BLAKE2b384_Init(blake2b_t *restrict x){ blake2b_init(x, 48, NULL, 0); }
void BLAKE2b512_Init(blake2b_t *restrict x){ blake2b_init(x, 64, NULL, 0); }

void *kBLAKE2b160_Init(BLAKE2b_KPARAMS){ return blake2b_init(x, 20, k, klen); }
void *kBLAKE2b256_Init(BLAKE2b_KPARAMS){ return blake2b_init(x, 32, k, klen); }
void *kBLAKE2b384_Init(BLAKE2b_KPARAMS){ return blake2b_init(x, 48, k, klen); }
void *kBLAKE2b512_Init(BLAKE2b_KPARAMS){ return blake2b_init(x, 64, k, klen); }

void blake2b_update(blake2b_t *restrict x, const void *restrict data, size_t len)
{
    size_t i;

    for(i=0; i<len; i++)
    {
        if( x->filled == sizeof(x->b) )
        {
            x->t += x->filled;
            blake2b_compress(x->h, x->b, x->t, 0);
            x->filled = 0;
        }

        x->b[x->filled++] = ((const uint8_t *)data)[i];
    }
}

void blake2b_final(blake2b_t *restrict x, void *restrict out, size_t t)
{
    uint8_t *ptr = out;
    size_t i;

    if( x->finalized ) goto finalized;

    x->t += x->filled;
    while( x->filled < sizeof(x->b) )
        x->b[x->filled++] = 0;

    blake2b_compress(x->h, x->b, x->t, 1);
    for(i=0; i<8; i++)
        *((uint64_t *)x->b + i) = htole64(x->h[i]);

    x->finalized = true;

finalized:
    if( out )
    {
        for(i=0; i<t; i++)
            ptr[i] = i<x->outlen ? x->b[i] : 0;
    }
}

static void *blake2s_init(
    blake2s_t *restrict x, size_t outlen,
    void const *restrict k, size_t keylen)
{
    size_t i;

    if( outlen > 32 || outlen < 1 || keylen > 32 ) return NULL;

    x->outlen = outlen;
    x->keylen = keylen;
    x->finalized = false;

    x->h[0] = 0x6a09e667;
    x->h[1] = 0xbb67ae85;
    x->h[2] = 0x3c6ef372;
    x->h[3] = 0xa54ff53a;
    x->h[4] = 0x510e527f;
    x->h[5] = 0x9b05688c;
    x->h[6] = 0x1f83d9ab;
    x->h[7] = 0x5be0cd19;

    x->h[0] ^= UINT32_C(0x01010000) ^ (x->keylen << 8) ^ x->outlen;
    x->t = 0;
    x->filled = 0;

    for(i=0; i<sizeof(x->b); i++) x->b[i] = 0;

    if( keylen > 0 )
    {
        blake2s_update(x, k, keylen);
        x->filled = sizeof(x->b);
    }

    return x;
}

void BLAKE2s128_Init(blake2s_t *restrict x){ blake2s_init(x, 16, NULL, 0); }
void BLAKE2s160_Init(blake2s_t *restrict x){ blake2s_init(x, 20, NULL, 0); }
void BLAKE2s224_Init(blake2s_t *restrict x){ blake2s_init(x, 28, NULL, 0); }
void BLAKE2s256_Init(blake2s_t *restrict x){ blake2s_init(x, 32, NULL, 0); }

void *kBLAKE2s128_Init(BLAKE2s_KPARAMS){ return blake2s_init(x, 16, k, klen); }
void *kBLAKE2s160_Init(BLAKE2s_KPARAMS){ return blake2s_init(x, 20, k, klen); }
void *kBLAKE2s224_Init(BLAKE2s_KPARAMS){ return blake2s_init(x, 28, k, klen); }
void *kBLAKE2s256_Init(BLAKE2s_KPARAMS){ return blake2s_init(x, 32, k, klen); }

void blake2s_update(blake2s_t *restrict x, const void *restrict data, size_t len)
{
    size_t i;

    for(i=0; i<len; i++)
    {
        if( x->filled == sizeof(x->b) )
        {
            x->t += x->filled;
            blake2s_compress(x->h, x->b, x->t, 0);
            x->filled = 0;
        }

        x->b[x->filled++] = ((const uint8_t *)data)[i];
    }
}

void blake2s_final(blake2s_t *restrict x, void *restrict out, size_t t)
{
    uint8_t *ptr = out;
    size_t i;

    if( x->finalized ) goto finalized;

    x->t += x->filled;
    while( x->filled < sizeof(x->b) )
        x->b[x->filled++] = 0;

    blake2s_compress(x->h, x->b, x->t, 1);
    for(i=0; i<8; i++)
        *((uint32_t *)x->b + i) = htole32(x->h[i]);

    x->finalized = true;

finalized:
    if( out )
    {
        for(i=0; i<t; i++)
            ptr[i] = i<x->outlen ? x->b[i] : 0;
    }
}

IntPtr iBLAKE2b160(int q){ return xBLAKE2b160(q); }
IntPtr iBLAKE2b256(int q){ return xBLAKE2b256(q); }
IntPtr iBLAKE2b384(int q){ return xBLAKE2b384(q); }
IntPtr iBLAKE2b512(int q){ return xBLAKE2b512(q); }

IntPtr iBLAKE2s128(int q){ return xBLAKE2s128(q); }
IntPtr iBLAKE2s160(int q){ return xBLAKE2s160(q); }
IntPtr iBLAKE2s224(int q){ return xBLAKE2s224(q); }
IntPtr iBLAKE2s256(int q){ return xBLAKE2s256(q); }

IntPtr ikBLAKE2b160(int q){ return xkBLAKE2b160(q); }
IntPtr ikBLAKE2b256(int q){ return xkBLAKE2b256(q); }
IntPtr ikBLAKE2b384(int q){ return xkBLAKE2b384(q); }
IntPtr ikBLAKE2b512(int q){ return xkBLAKE2b512(q); }

IntPtr ikBLAKE2s128(int q){ return xkBLAKE2s128(q); }
IntPtr ikBLAKE2s160(int q){ return xkBLAKE2s160(q); }
IntPtr ikBLAKE2s224(int q){ return xkBLAKE2s224(q); }
IntPtr ikBLAKE2s256(int q){ return xkBLAKE2s256(q); }
