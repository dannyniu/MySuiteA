/* DannyNiu/NJF, 2018-02-13. Public Domain. */

#include "../0-datum/endian.h"
#include "poly1305.h"

static void p1305bn_add(p1305bn_t a, const p1305bn_t b) // intentionally not restrict qualified. 
{
    register uint32_t u = 0, v;
    for(int i=0; i<5; i++)
    {
        v = b[i];
        if( (a[i] += u) < u ) u = 1; else u = 0;
        if( (a[i] += v) < v ) u += 1;
    }
}

static void p1305bn_modp(p1305bn_t x)
{
    uint64_t w[5] = {0};
    int i;

    for(i=0; i<5; i++) w[i] = x[i];

    w[0] += 5*(w[4]>>2); w[4] &= 3;
    for(i=1; i<5; i++) { w[i] += w[i-1]>>32; w[i-1] &= UINT64_C(0xffffffff); }

    for(i=0; i<5; i++) x[i] = (uint32_t)w[i];
}

static inline void p1305bn_scl(p1305bn_t out, p1305bn_t a, uint64_t x)
{
    // Multiply a by x and store the result of partial reduction in a. 
    
    uint64_t w[5] = {0};
    int i;

    // carry won't overflow for x <- [0,0x0fffffff]U{0x100000000}
    for(i=0; i<5; i++) { w[i] = a[i]*x; }
    for(i=1; i<5; i++) { w[i] += w[i-1]>>32; w[i-1] &= UINT64_C(0xffffffff); }

    w[0] += 5*(w[4]>>2); w[4] &= 3;
    for(i=1; i<5; i++) { w[i] += w[i-1]>>32; w[i-1] &= UINT64_C(0xffffffff); }

    for(i=0; i<5; i++) { out[i] = (uint32_t)w[i]; }
}

static void p1305bn_mul(p1305bn_t a, p1305bn_t b)
{
    int i, j;
    p1305bn_t m = {0}, n = {0};
    
    for(i=5; i-->0; )
    {
        p1305bn_scl(m, a, b[i]);
        for(j=0; j<i; j++) p1305bn_scl(m, m, 0x100000000);
        p1305bn_add(n, m);
    }
    p1305bn_modp(n);
    
    for(i=0; i<5; i++) a[i] = n[i];
}

void poly1305_init(poly1305_t *restrict poly1305, const void *restrict key)
{
    int i;
    const uint32_t *k = key;
    
    for(i=0; i<5; i++) poly1305->r[i] = poly1305->s[i] = poly1305->a[i] = 0;
    for(i=0; i<4; i++) {
        poly1305->r[i] = le32toh(k[i]);
        poly1305->s[i] = le32toh(k[i+4]);
    }
    poly1305->r[0] &= UINT32_C(0x0fffffff);
    poly1305->r[1] &= UINT32_C(0x0ffffffc);
    poly1305->r[2] &= UINT32_C(0x0ffffffc);
    poly1305->r[3] &= UINT32_C(0x0ffffffc);
}

static inline void p1305bn_addto(p1305bn_t a, uint32_t x, int i)
{
    register uint32_t u = (uint32_t)x;
    for(; i<5 && u; i++)
    {
        if( (a[i] += u) < u ) u = 1; else u = 0;
    }
}

void poly1305_1block(poly1305_t *restrict poly1305, const void *restrict data)
{
    if( data )
    {
        // data should be block-aligned, or word-aligned at least. 
        p1305bn_addto(poly1305->a, le32toh(((const uint32_t *)data)[0]), 0);
        p1305bn_addto(poly1305->a, le32toh(((const uint32_t *)data)[1]), 1);
        p1305bn_addto(poly1305->a, le32toh(((const uint32_t *)data)[2]), 2);
        p1305bn_addto(poly1305->a, le32toh(((const uint32_t *)data)[3]), 3);
        p1305bn_addto(poly1305->a, 1, 4);
    }
    
    p1305bn_mul(poly1305->a, poly1305->r);
}

void poly1305_final(poly1305_t *restrict poly1305)
{
    p1305bn_add(poly1305->a, poly1305->s);

    for(int i=0; i<5; i++) poly1305->r[i] = poly1305->s[i] = 0;
}
