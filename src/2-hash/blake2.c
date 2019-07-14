/* DannyNiu/NJF, 2018-12-23. Public Domain. */

#include "blake2.h"
#include "../1-symm/chacha.h"

static void blake2b_init(blake2b_t *restrict x, int outlen)
{
    size_t i;
    x->outlen = (uint8_t)outlen;
    
    x->h[0] = 0x6a09e667f3bcc908;
    x->h[1] = 0xbb67ae8584caa73b;
    x->h[2] = 0x3c6ef372fe94f82b;
    x->h[3] = 0xa54ff53a5f1d36f1;
    x->h[4] = 0x510e527fade682d1;
    x->h[5] = 0x9b05688c2b3e6c1f;
    x->h[6] = 0x1f83d9abfb41bd6b;
    x->h[7] = 0x5be0cd19137e2179;

    x->h[0] ^= 0x01010000 ^ x->outlen; // not supporting key.
    x->t = 0;
    x->filled = 0;

    for(i=0; i<sizeof(x->b); i++) x->b[i] = 0;
}

void BLAKE2b160_Init(blake2b_t *restrict x){ blake2b_init(x, 20); }
void BLAKE2b256_Init(blake2b_t *restrict x){ blake2b_init(x, 32); }
void BLAKE2b384_Init(blake2b_t *restrict x){ blake2b_init(x, 48); }
void BLAKE2b512_Init(blake2b_t *restrict x){ blake2b_init(x, 64); }

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

void blake2b_final(blake2b_t *restrict x, void *restrict out)
{
    size_t i;

    x->t += x->filled;
    while( x->filled < sizeof(x->b) )
        x->b[x->filled++] = 0;

    blake2b_compress(x->h, x->b, x->t, 1);
    for(i=0; i<x->outlen; i++)
        ((uint8_t *)out)[i] = (uint8_t)(
            x->h[i/sizeof(*x->h)] >> ((i % sizeof(*x->h)) * 8)
            );
}

static void blake2s_init(blake2s_t *restrict x, int outlen)
{
    size_t i;
    x->outlen = (uint8_t)outlen;
    
    x->h[0] = 0x6a09e667;
    x->h[1] = 0xbb67ae85;
    x->h[2] = 0x3c6ef372;
    x->h[3] = 0xa54ff53a;
    x->h[4] = 0x510e527f;
    x->h[5] = 0x9b05688c;
    x->h[6] = 0x1f83d9ab;
    x->h[7] = 0x5be0cd19;

    x->h[0] ^= 0x01010000 ^ x->outlen; // not supporting key.
    x->t = 0;
    x->filled = 0;

    for(i=0; i<sizeof(x->b); i++) x->b[i] = 0;
}

void BLAKE2s128_Init(blake2s_t *restrict x){ blake2s_init(x, 16); }
void BLAKE2s160_Init(blake2s_t *restrict x){ blake2s_init(x, 20); }
void BLAKE2s224_Init(blake2s_t *restrict x){ blake2s_init(x, 28); }
void BLAKE2s256_Init(blake2s_t *restrict x){ blake2s_init(x, 32); }

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

void blake2s_final(blake2s_t *restrict x, void *restrict out)
{
    size_t i;

    x->t += x->filled;
    while( x->filled < sizeof(x->b) )
        x->b[x->filled++] = 0;

    blake2s_compress(x->h, x->b, x->t, 1);
    for(i=0; i<x->outlen; i++)
        ((uint8_t *)out)[i] = (uint8_t)(
            x->h[i/sizeof(*x->h)] >> ((i % sizeof(*x->h)) * 8)
            );
}

uintptr_t iBLAKE2b160(int q){ return _iBLAKE2b160(q); }
uintptr_t iBLAKE2b256(int q){ return _iBLAKE2b256(q); }
uintptr_t iBLAKE2b384(int q){ return _iBLAKE2b384(q); }
uintptr_t iBLAKE2b512(int q){ return _iBLAKE2b512(q); }

uintptr_t iBLAKE2s128(int q){ return _iBLAKE2s128(q); }
uintptr_t iBLAKE2s160(int q){ return _iBLAKE2s160(q); }
uintptr_t iBLAKE2s224(int q){ return _iBLAKE2s224(q); }
uintptr_t iBLAKE2s256(int q){ return _iBLAKE2s256(q); }
