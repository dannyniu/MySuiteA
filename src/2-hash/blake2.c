/* DannyNiu/NJF, 2018-12-23. Public Domain. */

#include "blake2.h"
#include "../1-symm/chacha.h"
#include "../0-datum/endian.h"

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
