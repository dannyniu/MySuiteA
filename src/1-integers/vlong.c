/* DannyNiu/NJF, 2020-12-25. Public Domain. */

#include "vlong.h"

// MARK: == Additive Expressions ==

// This kernel should be placed in a function with
// at least following 2 arguments:
// - vlong_t *out,
// - vlong_t const *a,
// The function would calculate an additive expression
// of ``a'' and the following operand of some type:
// - <?> b,
// optionally using some additional info.
//
// A bit of note on mathematical correctness:
// The sum of 3 32-bit operands won't overflow a
// 64-bit word, so sign-extending is safe here,
// and it's usage-compatible with subtraction.
#define VLONG_ADD_KERNEL(BEXPR)                 \
    vlong_size_t i;                             \
    uint64_t x = 0;                             \
                                                \
    for(i=0; i<out->c; i++)                     \
    {                                           \
        x += i < a->c ? a->v[i] : 0;            \
        BEXPR;                                  \
        out->v[i] = (uint32_t)x;                \
        x >>= 32;                               \
        x = (uint64_t)(int64_t)(int32_t)x;      \
    }                                           \
                                                \
    return out;

vlong_t *vlong_adds(
    vlong_t *out,
    vlong_t const *a,
    int64_t b, vlong_size_t s)
{
    VLONG_ADD_KERNEL(x += (i == s ? b : 0));
}

vlong_t *vlong_addv(
    vlong_t *out,
    vlong_t const *a,
    vlong_t const *b)
{
    VLONG_ADD_KERNEL(x += (i < b->c ? b->v[i] : 0));
}

vlong_t *vlong_subv(
    vlong_t *out,
    vlong_t const *a,
    vlong_t const *b)
{
    VLONG_ADD_KERNEL(x -= (i < b->c ? b->v[i] : 0));
}

// MARK: == Scalar Multiplication Expressions ==

vlong_t *vlong_mulx(vlong_t *out, vlong_t const *a)
{
    vlong_size_t i = out->c;

    while( --i < out->c ) // ``i'' is unsigned, thus the weird condition.
    {
        uint32_t x = 0;
        if( i <= a->c && i > 0 )
            x = a->v[i-1];

        out->v[i] = x;
    }

    return out;
}

vlong_t *vlong_muls(vlong_t *out, vlong_t const *a, uint32_t b, int accum)
{
    vlong_size_t i;
    uint64_t x;

    for(i=0, x=0; i<out->c; i++)
    {
        x += i < a->c ? a->v[i] * (uint64_t)b : 0;
        if( accum ) x += out->v[i];
        out->v[i] = (uint32_t)x;
        x >>= 32;
    }

    return out;
}

// MARK: == Generic Division ==

static inline uint32_t vlong_word_shifted(
    vlong_t const *b,
    vlong_size_t i,
    vlong_size_t s)
{
    vlong_size_t w = s/32, r = s%32;
    uint32_t v = i-w < b->c ? b->v[i-w] : 0;
    if( r ) v = (v << r) | (i-w-1 < b->c ? b->v[i-w-1] >> (32 - r) : 0);
    return v;
}

// Returns
// - 0 if a == b,
// - 1 if a > b, and
// - 2 if a < b.
static int vlong_cmps(uint32_t a, uint32_t b)
{
    uint64_t x = a, y;
    x -= b;

    // (attempted) constant-time implementation.
    y = (x >> 32) & 1;
    x = x | (x >> 16);
    x = x | (x >>  8);
    x = x | (x >>  4);
    x = x | (x >>  2);
    x = x | (x >>  1);
    x &= 1;
    x &= ~y;
    
    return x | (y << 1);
}

// Same as above.
static int vlong_cmpv_shifted(
    vlong_t const *a,
    vlong_t const *b,
    vlong_size_t s)
{
    vlong_size_t w = (s + 31)/32;
    vlong_size_t t = a->c > (b->c + w) ? a->c : (b->c + w);
    uint32_t u, v;
    int res = 0, mask;

    while( t-- )
    {
        // (attempted) constant-time implementation.
        u = t-0 < a->c ? a->v[t-0] : 0;
        v = vlong_word_shifted(b, t, s);
        mask = (1 & ((res >> 1) | res)) * 3;
        mask = ~mask;
        mask &= vlong_cmps(u, v);
        res |= mask;
    }

    return res;
}

static vlong_t *vlong_shift_1bit(vlong_t *x, int b)
{
    vlong_size_t i = x->c;

    while( i-- )
    {
        x->v[i] =
            (x->v[i] << 1) |
            (i ? x->v[i-1] >> 31 : b & 1);
    }

    return x;
}

static vlong_t *vlong_sub_shifted_masked(
    vlong_t *out,
    vlong_t const *a,
    vlong_t const *b,
    vlong_size_t s,
    uint32_t mask) // ``mask'' shall be either 1 or 0.
{
    VLONG_ADD_KERNEL(x -= (vlong_word_shifted(b, i, s) & (0 - mask)));
    
}

vlong_t *vlong_divv(
    vlong_t *restrict rem,
    vlong_t *restrict quo,
    vlong_t const *a,
    vlong_t const *b)
{
    vlong_size_t i;
    int cmp;

    if( quo && quo->c < a->c ) return NULL;
    if(        rem->c < b->c ) return NULL;

    for(i=0; i<rem->c; i++) rem->v[i] = 0;
    for(i=0; i<quo->c; i++) quo->v[i] = 0;
    
    i = a->c * 32;

    while( i-- )
    {
        vlong_shift_1bit(rem, a->v[i >> 5] >> (i & 31));
        cmp = vlong_cmpv_shifted(rem, b, 0);
        cmp = ~(cmp >> 1) & 1;
        vlong_sub_shifted_masked(rem, rem, b, 0, cmp);
        if( quo ) quo->v[i >> 5] |= cmp << (i & 31);
    }

    return rem;
}

vlong_t *vlong_remv_inplace(vlong_t *rem, vlong_t const *b)
{
    vlong_size_t i;
    int cmp;
    
    if( rem->c < b->c ) return NULL;

    i = rem->c * 32;

    while( i-- )
    {
        cmp = vlong_cmpv_shifted(rem, b, i);
        cmp = ~(cmp >> 1) & 1;
        vlong_sub_shifted_masked(rem, rem, b, i, cmp);
    }

    return rem;
}

// MARK: == Multiplicative Expressions ==

vlong_t *vlong_mulv(
    vlong_t *restrict out,
    vlong_t const *a,
    vlong_t const *b,
    vlong_modfunc_t modfunc,
    void *restrict mod_ctx)
{
    vlong_size_t i;

    for(i=0; i<out->c; i++) out->v[i] = 0;

    for(i=b->c; i--; )
    {
        vlong_muls(out, a, b->v[i], true);
        if( modfunc && !modfunc(out, mod_ctx) ) return NULL;
        
        if( i )
        {
            vlong_mulx(out, out);
            if( modfunc && !modfunc(out, mod_ctx) ) return NULL;
        }
    }

    return out;
}