/* DannyNiu/NJF, 2021-02-16. Public Domain. */

#include "MillerRabin.h"

// 2021-06-05:
// - This function doesn't need to be side-channel resistant,
//   as RSA isn't usually used for ephemeral key encapsulation

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

static int vlong_ge_shifted(
    vlong_t const *a,
    vlong_t const *b,
    vlong_size_t s)
{
    vlong_size_t w = (s + 31) / 32;
    vlong_size_t t = a->c > (b->c + w) ? a->c : (b->c + w);
    uint32_t u, v;

    while( t-- )
    {
        u = t-0 < a->c ? a->v[t-0] : 0;
        v = vlong_word_shifted(b, t, s);
        if( u > v ) return 1;
        if( u < v ) return 0;
    }

    return 1;
}

static inline vlong_t *vlong_sub_shifted(
    vlong_t *out,
    vlong_t const *a,
    vlong_t const *b,
    vlong_size_t s) // ``mask'' shall be either 1 or 0.
{
    vlong_size_t i;
    uint64_t x = 0;

    for(i=0; i<out->c; i++)
    {
        x += i < a->c ? a->v[i] : 0;
        x -= vlong_word_shifted(b, i, s);
        out->v[i] = (uint32_t)x;
        x >>= 32;
        x = (uint64_t)(int64_t)(int32_t)x;
    }

    return out;
}

vlong_t *vlong_remv_inplace_fast(vlong_t *rem, vlong_t const *b)
{
    vlong_size_t i, t;

    if( rem->c < b->c ) return NULL;

    i = 0;
    for(t=  b->c; t &&   !b->v[--t]; ) i++;
    for(t=rem->c; t && !rem->v[--t]; ) i--;

    if( i > rem->c ) return rem;
    else i = (i + 1) * 32;

    while( i-- )
    {
        if( vlong_ge_shifted(rem, b, i) )
            vlong_sub_shifted(rem, rem, b, i);
    }

    return rem;
}

int MillerRabin(
    vlong_t const *restrict w,
    int iterations,
    vlong_t *restrict tmp1, // temporary variables are
    vlong_t *restrict tmp2, // allocated by the caller
    vlong_t *restrict tmp,
    GenFunc_t rng, void *restrict rng_ctx)
{
    vlong_modfunc_t modfunc = (vlong_modfunc_t)vlong_remv_inplace_fast;
    vlong_size_t a, f, i, j, n;

    n = tmp1->c = tmp2->c = tmp->c = w->c;
    f = n * 32;

    for(a=1; a<f; a++)
    {
        if( (w->v[a / 32] >> (a % 32)) & 1 )
            break;
    }

    // synthesized variable: m = (w - 1) / (2 ** a).

iteration_enter:
    if( !(iterations--) ) return 1;

regen: // Generate b in ]1, w-1[.
    rng(rng_ctx, tmp1->v, n * sizeof(uint32_t));

    for(i=n; --i>0; )
    {
        if( tmp1->v[i] )
            break;
    }

    if( i == 0 && tmp1->v[0] <= 1 ) goto regen;
    if( i > 0 ) while( tmp1->v[i] && tmp1->v[i] >= w->v[i] ) tmp1->v[i] >>= 1;
    tmp1->v[0] |= 0xAA55;

    // z := b ** m (mod w).
    for(i=1; i<n; i++) tmp->v[i] = 0; tmp->v[0] = 1;
    for(i=a;;)
    {
        uint32_t mask = (w->v[i / 32] >> (i % 32)) & 1;

        if( mask )
        {
            vlong_mulv_masked(
                tmp2,
                tmp, tmp1,
                1, modfunc, w);

            for(j=0; j<n; j++) tmp->v[j] = tmp2->v[j];
        }

        if( ++i >= f ) break;

        vlong_mulv_masked(
            tmp2,
            tmp1, tmp1,
            1, modfunc, w);

        for(j=0; j<n; j++) tmp1->v[j] = tmp2->v[j];

        continue;
    }

    // if z === +/- 1 (mod w): goto iteration_enter.
    for(i=n; --i>0; )
    {
        if( tmp->v[i] )
            break;
    }
    if( i == 0 && tmp->v[0] == 1 ) goto iteration_enter;

    vlong_adds(tmp1, tmp, 1, 0);
    for(i=0; i<n; i++) if( tmp1->v[i] != w->v[i] ) break;
    if( i == n ) goto iteration_enter;

    for(j=1; j<a; j++)
    {
        vlong_mulv_masked(tmp2, tmp, tmp, 1, modfunc, w);
        for(i=0; i<n; i++) tmp->v[i] = tmp2->v[i];

        // if z === +1 (mod w): return COMPOSITE.
        // if z === -1 (mod w): goto iteration_enter.
        for(i=n; --i>0; )
        {
            if( tmp->v[i] )
                break;
        }
        if( i == 0 && tmp->v[0] == 1 ) return 0;

        vlong_adds(tmp1, tmp, 1, 0);
        for(i=0; i<n; i++) if( tmp1->v[i] != w->v[i] ) break;
        if( i == n ) goto iteration_enter;
    }

    // Cannot be identified as prime.
    return 0;
}
