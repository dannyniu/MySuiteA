/* DannyNiu/NJF, 2022-10-02. Public Domain. */

#include "galois128.h"

#include "../0-datum/endian.h"
#include <altivec.h>

typedef vector unsigned __int128 v128;
typedef vector unsigned long long v64x2;

static inline v128 bytes_mirror(v128 x)
{
    v128 mask;

    mask[0] = 0xaaaa;
    mask[0] = mask[0]<<16 | mask[0];
    mask[0] = mask[0]<<32 | mask[0];
    mask[0] = mask[0]<<64 | mask[0];
    x = (x & mask)>>1 | (x & mask>>1)<<1;

    mask[0] = 0xcccc;
    mask[0] = mask[0]<<16 | mask[0];
    mask[0] = mask[0]<<32 | mask[0];
    mask[0] = mask[0]<<64 | mask[0];
    x = (x & mask)>>2 | (x & mask>>2)<<2;

    mask[0] = 0xf0f0;
    mask[0] = mask[0]<<16 | mask[0];
    mask[0] = mask[0]<<32 | mask[0];
    mask[0] = mask[0]<<64 | mask[0];
    x = (x & mask)>>4 | (x & mask>>4)<<4;

    return x;
}

static v128 galois128_mul_ppc(v128 x, v128 y)
{
    register v128 a, b, c;
    register v64x2 p = (v64x2){0, 0x0087};

    x = bytes_mirror(x);
    y = bytes_mirror(y);

    a = vec_pmsum_be((v64x2){0,x[0]}, (v64x2){0,y[0]});
    b = vec_pmsum_be((v64x2){x[0],x[0]>>64}, (v64x2){y[0]>>64,y[0]});
    a[0] ^= b[0]<<64;

    c = vec_pmsum_be(p, (v64x2){0,b[0]>>64});
    a ^= c;

    b = vec_pmsum_be((v64x2){0,x[0]>>64}, (v64x2){0,y[0]>>64});
    c = vec_pmsum_be(p, (v64x2){0,b[0]});
    a[0] ^= c[0];
    c = vec_pmsum_be(p, (v64x2){0,b[0]>>64});
    a[0] ^= c[0]<<64;
    c = vec_pmsum_be(p, (v64x2){0,c[0]>>64});
    a[0] ^= c[0];

    return bytes_mirror(a);
}

void galois128_hash1block_ni(
    void *restrict Y,
    void const *restrict H,
    void const *restrict X)
{
    register v128 y={0}, h={0}, x={0};

    y[0] ^= le64toh(((const uint64_t *)Y)[1]); y[0] <<= 64;
    y[0] ^= le64toh(((const uint64_t *)Y)[0]);

    if( X ) {
        x[0] ^= le64toh(((const uint64_t *)X)[1]); x[0] <<= 64;
        x[0] ^= le64toh(((const uint64_t *)X)[0]);
        y[0] ^= x[0];
    }

    h[0] ^= le64toh(((const uint64_t *)H)[1]); h[0] <<= 64;
    h[0] ^= le64toh(((const uint64_t *)H)[0]);

    y = galois128_mul_ppc(y, h);
    ((uint64_t *)Y)[0] = htole64((uint64_t)(y[0]));
    ((uint64_t *)Y)[1] = htole64((uint64_t)(y[0]>>64));
}

#define IntrinSelf
#include "galois128.c"
