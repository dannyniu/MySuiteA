/* DannyNiu/NJF, 2018-02-26. Public Domain. */

#include "bignum.h"

uint32_t bn_add(long n, bn_t *out, const bn_t *a, const bn_t *b, uint64_t x)
{
    for(long i=0; i<n; i++) {
        if( a ) x += a->w[i];
        if( b ) x += b->w[i];
        out->w[i] = x;
        x >>= 32;
    }

    return x;
}

int32_t bn_sub(long n, bn_t *out, const bn_t *a, const bn_t *b, uint64_t x)
{
    for(long i=0; i<n; i++) {
        if( a ) x += a->w[i];
        if( b ) x -= b->w[i];
        out->w[i] = x;
        x = (int64_t)(int32_t)(x>>32); // sign-extending.
    }

    return x;
}

uint32_t bn_imul(long n, bn_t *out, const bn_t *a, uint64_t b)
{
    uint64_t x=0;

    for(long i=0; i<n; i++) {
        x >>= 32;
        x += a->w[i] * b;
        if( out != a ) x += out->w[i];
        out->w[i] = x;
    }

    return x;
}

uint32_t bn_idiv(long n, bn_t *out, const bn_t *a, uint64_t b)
{
    uint64_t dividend=0, divisor=b;

    for(long i=n; i--; ) {
        dividend <<= 32;
        dividend += a->w[i];
        out->w[i] = dividend / divisor;
        dividend %= divisor;
    }

    return dividend; // the remainder. 
}

void bn_mul(long n,
            bn_t *restrict out,
            const bn_t *a,
            const bn_t *b)
{
    for(long i=0; i<n; i++) out->w[i] = 0;

    for(long i=0; i<n; i++)
        bn_imul(n-i, (bn_t *)&out->w[i], a, b->w[i]);

    return;
}

static inline uint32_t bn_ishift(long n, const bn_t *x, long s, long i)
{
    // left-shift x in-place s bits without modifying source and
    // retreive i'th word. 
    // assume 0<= i <n.

    uint32_t ret = 0;
    
    i -= s/32;
    s %= 32;

    if( 0 <= i && i < n ) ret |= x->w[i] << s;
    if( 0 < i && i <= n ) ret |= s ? x->w[i-1] >> (32-s) : 0;
    
    return ret;
}

static int bn_shift_ge(long n, long s, const bn_t *a, const bn_t *b)
{
    // returns a<=b*2^s.

    for(long i=n+(s+31)/32; i--; ) {
        uint32_t u = i<n ? a->w[i] : 0;
        uint32_t v = bn_ishift(n, b, s, i);
        if( u < v ) { return 0; } else if( u > v ) { break; }
    }
    return 1;
}

static int bn_shift_sub(long n, long s, bn_t *out, const bn_t *a, const bn_t *restrict b)
{
    // computes out = a-b*2^s.

    uint64_t x = 0;
    
    for(long i=0; i<n; i++) {
        if( a ) x += a->w[i];
        if( b ) x -= bn_ishift(n, b, s, i);
        out->w[i] = x;
        x = (int64_t)(int32_t)(x>>32); // sign-extending.
    }

    return x;
}

void bn_div(long n,
            bn_t *restrict quo,
            bn_t *rem,
            const bn_t *a,
            const bn_t *restrict b)
{
    for(long i=0; i<n; i++) {
        if( quo ) quo->w[i] = 0;
        rem->w[i] = a->w[i];
    }
    
    for(long t=n*32; t-->0; ) {
        if( bn_shift_ge(n, t, rem, b) ) {
            bn_shift_sub(n, t, rem, rem, b);
            if( quo ) quo->w[t/32] |= (uint32_t)1 << t%32;
        }
    }
}
