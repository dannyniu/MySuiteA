/* DannyNiu/NJF, 2018-02-11. Public Domain. */

#include "galois128.h"

#include "../0-datum/endian.h"
#include <arm_neon.h>

static inline poly128_t bytes_mirror(poly128_t x)
{
    poly128_t mask;
    
    mask = 0xaaaa;
    mask = mask<<16 | mask;
    mask = mask<<32 | mask;
    mask = mask<<64 | mask;
    x = (x & mask)>>1 | (x & mask>>1)<<1;
    
    mask = 0xcccc;
    mask = mask<<16 | mask;
    mask = mask<<32 | mask;
    mask = mask<<64 | mask;
    x = (x & mask)>>2 | (x & mask>>2)<<2;
    
    mask = 0xf0f0;
    mask = mask<<16 | mask;
    mask = mask<<32 | mask;
    mask = mask<<64 | mask;
    x = (x & mask)>>4 | (x & mask>>4)<<4;
    
    return x;
}

static poly128_t galois128_mul_x86(poly128_t x, poly128_t y)
{
    register poly128_t a, b, c;
    register poly64_t p = 0x0087;

    x = bytes_mirror(x), y = bytes_mirror(y);

    a = vmull_p64(x, y);
    b = vmull_p64(x, y>>64);
    b ^= vmull_p64(x>>64, y);
    a ^= b<<64;
    
    c = vmull_p64(p, b>>64);
    a ^= c;

    b = vmull_p64(x>>64, y>>64);
    c = vmull_p64(p, b);
    a ^= c;
    c = vmull_p64(p, b>>64);
    a ^= c<<64;
    c = vmull_p64(p, c>>64);
    a ^= c;

    return bytes_mirror(a);
}

void galois128_hash1block(void *restrict Y,
                          const void *restrict H,
                          const void *restrict X)
{
    register poly128_t y=0, h=0, x=0;

    y ^= le64toh(((uint64_t *)Y)[1]); y <<= 64;
    y ^= le64toh(((uint64_t *)Y)[0]);

    if( X ) {
        x ^= le64toh(((uint64_t *)X)[1]); x <<= 64;
        x ^= le64toh(((uint64_t *)X)[0]);
        y ^= x;
    }

    h ^= le64toh(((uint64_t *)H)[1]); h <<= 64;
    h ^= le64toh(((uint64_t *)H)[0]);

    y = galois128_mul_x86(y, h);
    ((uint64_t *)Y)[0] = htole64(y);
    ((uint64_t *)Y)[1] = htole64(y>>64);
}
