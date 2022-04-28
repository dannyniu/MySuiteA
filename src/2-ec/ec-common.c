/* DannyNiu/NJF, 2022-04-27. Public Domain. */

#include "ec-common.h"

vlong_t *ecp_imod_inplace(vlong_t *rem, const ecp_imod_aux_t *aux)
{
    vlong_size_t i;
    uint32_t neg = -((rem->v[rem->c - 1] >> 31) & 1);
    uint32_t z = 0;
    uint64_t x = 0;

    // the following line is a addition for
    // elliptic-curve cryptography.
    const vlong_t *b = aux->mod_ctx;

    // imod(x,p) := x >= 0 ? x % p : (p - (-x % p));

    for(i=0; i<rem->c; i++) rem->v[i] ^= neg;
    vlong_adds(rem, rem, neg&1, 0);

    aux->modfunc(rem, aux->mod_ctx);

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

vlong_t *vlong_modexpv_shiftadded(
    vlong_t *restrict out,
    vlong_t const *x,
    vlong_t *restrict tmp1,
    vlong_t *restrict tmp2,
    vlong_modfunc_t modfunc,
    vlong_t const *mod_ctx,
    int32_t addend,
    short shift)
{
    vlong_size_t f, i, j, n;

    vlong_t const *e = mod_ctx; // code layout eye candy.
    uint64_t w = (uint64_t)e->v[0] + addend;
    uint32_t mask;

    if( out->c != tmp1->c || tmp1->c != tmp2->c )
        return NULL;

    f = e->c * 32;
    n = out->c;

    for(i=0; i<n; i++)
    {
        // 2021-06-05:
        // 2 statements re-ordered to ensure copy won't be inconsistent,
        // and that ``base'' can be reused (e.g. aliasing ``out'' to ``base'').
        // 2022-02-06:
        // ``base'' renamed to ``x''.
        tmp1->v[i] = i < x->c ? x->v[i] : 0;
        out->v[i] = i ? 0 : 1;
    }

    for(i=shift;;)
    {
        mask = (w >> (i % 32)) & 1;

        vlong_mulv_masked(
            tmp2,
            out, tmp1,
            mask, modfunc, mod_ctx);

        for(j=0; j<n; j++) out->v[j] = tmp2->v[j];

        if( ++i >= f ) break; // 2022-02-24: this could be a false assumption.
        if( i % 32 == 0 ) w = (w >> 32) + e->v[i / 32];

        vlong_mulv_masked(
            tmp2,
            tmp1, tmp1,
            1, modfunc, mod_ctx);

        for(j=0; j<n; j++) tmp1->v[j] = tmp2->v[j];

        continue;
    }

    return out;
}
