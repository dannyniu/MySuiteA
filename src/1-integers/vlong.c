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

// Returns
// - 0 if a == b,
// - 1 if a > b, and
// - 2 if a < b.
int vlong_cmps(uint32_t a, uint32_t b)
{
    uint32_t x;
    uint64_t y;

    y = a;
    y -= b;
    x = y;

    // (attempted) constant-time implementation.
    y = (y >> 32) & 1;
    
    // Per suggestion by @fgrieu at https://crypto.stackexchange.com/q/88233 
    x = x | (x >> 16);
    x &= 0xffffU;
    x = -(1 ^ ((x ^ (x - 1)) >> 31));

    x &= 1;
    x &= ~y;
    
    return x | (y << 1);
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

// Same as ``vlong_cmps'' above.
static int vlong_cmpv_shifted(
    vlong_t const *a,
    vlong_t const *b,
    vlong_size_t s)
{
    vlong_size_t w = (s + 31) / 32;
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

    // It explicitly designed such that ``quo'' is
    // an optional argument. Formmatted accordingly.
    for(i=0;        i<rem->c; i++) rem->v[i] = 0;
    for(i=0; quo && i<quo->c; i++) quo->v[i] = 0;
    
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

vlong_t *vlong_remv_inplace(vlong_t *rem, const vlong_t *b)
{
    vlong_size_t i;
    int cmp;
    
    if( rem->c < b->c ) return NULL;

    // 2021-06-05:
    // 1 Optimization applied, because
    // most uses of this function are
    // based on public ``b''s
    for(i=b->c; i && !b->v[--i]; );
    i = (1 + rem->c - i) * 32;

    while( i-- )
    {
        cmp = vlong_cmpv_shifted(rem, b, i);
        cmp = ~(cmp >> 1) & 1;
        vlong_sub_shifted_masked(rem, rem, b, i, cmp);
    }

    return rem;
}

vlong_t *vlong_imod_inplace(vlong_t *rem, const vlong_t *b)
{
    vlong_size_t i;
    uint32_t neg = -((rem->v[rem->c - 1] >> 31) & 1);
    uint32_t z = 0;
    uint64_t x = 0;

    // imod(x,p) := x >= 0 ? x % p : (p - (-x % p));
    
    for(i=0; i<rem->c; i++) rem->v[i] ^= neg;
    vlong_adds(rem, rem, neg&1, 0);

    vlong_remv_inplace(rem, b);

    for(i=0; i<rem->c; i++) z |= rem->v[i];
    
    // Per suggestion by @fgrieu at https://crypto.stackexchange.com/q/88233
    z |= z >> 16;
    z &= 0xffffU;
    z = -(1 ^ ((z ^ (z - 1)) >> 31));
    neg &= z;

    for(i=0; i<rem->c; i++)
    {
        uint32_t u, v;
        u = i < rem->c ? rem->v[i] : 0;
        v = i <   b->c ?   b->v[i] : 0;
        
        x += (~neg & u) | (neg & v);
        x -= (neg & u);
        rem->v[i] = (uint32_t)x;
        
        x >>= 32;
        x = (uint64_t)(int64_t)(int32_t)x;
    }
    return rem;
}

// MARK: == Multiplicative Expressions ==

vlong_t *vlong_mulv_masked(
    vlong_t *restrict out,
    vlong_t const *a,
    vlong_t const *b,
    uint32_t mask,
    vlong_modfunc_t modfunc,
    const void *restrict mod_ctx)
{
    vlong_size_t i;

    uint32_t bmask = 0 - mask, umask = ~bmask;

    for(i=0; i<out->c; i++) out->v[i] = 0;

    for(i=b->c; i--; )
    {
        uint32_t bv = i ? 0 : 1;
        bv = (bv & umask) | (b->v[i] & bmask);
        
        vlong_muls(out, a, bv, true);
        if( modfunc && !modfunc(out, mod_ctx) ) return NULL;
        
        if( i )
        {
            vlong_mulx(out, out);
            if( modfunc && !modfunc(out, mod_ctx) ) return NULL;
        }
    }

    return out;
}

// MAKR: == Modular Exponentiation ==

vlong_t *vlong_modexpv(
    vlong_t *restrict out,
    vlong_t const* base,
    vlong_t const* e,
    vlong_t *restrict tmp1, // temporary variables are
    vlong_t *restrict tmp2, // allocated by the caller
    vlong_modfunc_t modfunc,
    const void *restrict mod_ctx)
{
    vlong_size_t f, i, j, n;
    
    if( out->c != tmp1->c || tmp1->c != tmp2->c )
        return NULL;

    f = e->c * 32;
    n = out->c;

    for(i=0; i<n; i++)
    {
        // 2021-06-05:
        // 2 statements re-ordered to ensure copy won't be inconsistent,
        // and that ``base'' can be reused (e.g. aliasing ``out'' to ``base'').
        tmp1->v[i] = i < base->c ? base->v[i] : 0;
        out->v[i] = i ? 0 : 1;
    }
    
    for(i=0;;)
    {
        uint32_t mask = (e->v[i / 32] >> (i % 32)) & 1;

        vlong_mulv_masked(
            tmp2,
            out, tmp1,
            mask, modfunc, mod_ctx);

        for(j=0; j<n; j++) out->v[j] = tmp2->v[j];

        if( ++i >= f ) break;
        
        vlong_mulv_masked(
            tmp2,
            tmp1, tmp1,
            1, modfunc, mod_ctx);

        for(j=0; j<n; j++) tmp1->v[j] = tmp2->v[j];

        continue;
    }
    
    return out;
}
