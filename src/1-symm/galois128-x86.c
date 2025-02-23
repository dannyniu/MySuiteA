/* DannyNiu/NJF, 2018-02-11. Public Domain. */

#include "galois128.h"
#include <x86intrin.h>

static inline __m128i bytes_mirror(__m128i x)
{
    x = _mm_srli_epi16((x & _mm_set1_epi8('\xaa')),1) | _mm_slli_epi16((x & _mm_set1_epi8('\x55')),1);
    x = _mm_srli_epi16((x & _mm_set1_epi8('\xcc')),2) | _mm_slli_epi16((x & _mm_set1_epi8('\x33')),2);
    x = _mm_srli_epi16((x & _mm_set1_epi8('\xf0')),4) | _mm_slli_epi16((x & _mm_set1_epi8('\x0f')),4);
    return x;
}

static __m128i galois128_mul_x86(__m128i x, __m128i y)
{
    register __m128i
        a, b, c,
        p = _mm_set_epi8(0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, '\x87');

    x = bytes_mirror(x);
    y = bytes_mirror(y);

    a = _mm_clmulepi64_si128(x, y, 0x00);
    b = _mm_clmulepi64_si128(x, y, 0x01);
    b ^=_mm_clmulepi64_si128(x, y, 0x10);
    a ^= _mm_slli_si128(b, 8); // 8 octets = 64 bits.

    c = _mm_clmulepi64_si128(p, b, 0x10);
    a ^= c;

    b = _mm_clmulepi64_si128(x, y, 0x11);
    c = _mm_clmulepi64_si128(p, b, 0x00);
    a ^= c;
    c = _mm_clmulepi64_si128(p, b, 0x10);
    a ^= _mm_slli_si128(c, 8);
    c = _mm_clmulepi64_si128(p, c, 0x10);
    a ^= c;

    return bytes_mirror(a);
}

void galois128_hash1block_ni(
    void *restrict Y,
    void const *restrict H,
    void const *restrict X)
{
    register __m128i y, h;
    y = _mm_loadu_si128(Y); if( X ) y ^= _mm_loadu_si128(X);
    h = _mm_loadu_si128(H);

    _mm_storeu_si128(Y, galois128_mul_x86(y, h));
}

#define IntrinSelf
#include "galois128.c"
