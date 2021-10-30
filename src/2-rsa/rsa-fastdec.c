/* DannyNiu/NJF, 2021-07-27. Public Domain. */
// Implementation of [QC82] fast decipherment.

#include "rsa.h"
#include "../0-exec/struct-delta.c.h"

// blueprint
// # uppercases modulus-sized, lowercase factor-sized.
// # private-key components are prefixed with apostrophe.
// # index suffixes follow underscore.
// # flow-control statements in square brackets.
// [begin: C, allocate: M, R, h, m, t]
// h := divv    C, 'r_1
// M := modexpv h, 'd_1 (mod: 'r_i, tmpvars: t, m)
// R := 'r_1
// [for i := 2..#primes]:
//     h := divv    C, 'r_i
//     h := modexpv h, 'd_i (mod: 'r_i, tmpvars: t, m) ; h can be aliased.
//     m := divv    M, 'r_i
//     m := subv    h, m    (mod: 'r_i)
//     h := mulv    m, 't_i (mod: 'r_i)
//     [vecop<len(h)>] M += muls R, h ; implement raw.
//     [reuse: h, m, t] R *= 'r_i
// [return: M]

vlong_t *rsa_fastdec(RSA_Priv_Ctx_Hdr_t *restrict x)
{
    RSA_Priv_Base_Ctx_t *bx = &x->base;
    RSA_OtherPrimeInfo_t *px = x->primes_other;

    uint32_t modulus_bits = bx->modulus_bits;
    uint32_t bits_per_prime = modulus_bits / (bx->count_primes_other + 2);
    
    vlong_size_t vlsize_modulus = (modulus_bits + 32 * 2 - 1) / 32;
    vlong_size_t vlsize_factor = (bits_per_prime + 32 * 2 - 1) / 32;
    vlong_size_t a, b;

    int i, j;
    uint32_t *ul;
    
    vlong_t *C = DeltaTo(bx, offset_w1); // set to C.
    vlong_t *M = DeltaTo(bx, offset_w2); // set to M.
    vlong_t *R = DeltaTo(bx, offset_w3); // allocated for R.

    vlong_t *ri, *di, *ti;

    vlong_t *h, *m, *t;
    ul = (uint32_t *)R + R->c + 1;
    
    h = (void *)ul;
    h->c = vlsize_factor;
    ul += h->c + 1;
    
    m = (void *)ul;
    m->c = vlsize_factor;
    ul += m->c + 1;
    
    t = (void *)ul;
    t->c = vlsize_factor;
    ul += t->c + 1;

    vlong_divv(h, NULL, C, DeltaTo(bx, offset_q));
    vlong_modexpv(h, h, DeltaTo(bx, offset_dQ), t, m,
                  (vlong_modfunc_t)vlong_remv_inplace,
                  DeltaTo(bx, offset_q));

    b = h->c;
    for(a=0; a<M->c; a++)
        M->v[a] = a < b ? h->v[a] : 0;
    
    b = ((vlong_t *)DeltaTo(bx, offset_q))->c;
    for(a=0; a<R->c; a++)
        R->v[a] = a < b ? ((vlong_t *)DeltaTo(bx, offset_q))->v[a] : 0;
    
    for(i=0; (unsigned)i<=bx->count_primes_other; i++)
    {
        j = i - 1;
        ri = DeltaAdd(x, px[j].offset_r);
        di = DeltaAdd(x, px[j].offset_d);
        ti = DeltaAdd(x, px[j].offset_t);

        vlong_divv(h, NULL, C, ri);
        vlong_modexpv(h, h, di, t, m,
                      (vlong_modfunc_t)vlong_remv_inplace, ri);

        vlong_divv(m, NULL, M, ri);
        vlong_subv(m, h, m);
        vlong_imod_inplace(m, ri);

        vlong_mulv_masked(h, m, ti, 1,
                   (vlong_modfunc_t)vlong_remv_inplace, ri);

        // 2021-09-11:
        // This loop probably has some problem.
        // Investigate and fix.
        for(a=0; a<h->c; a++)
        {
            uint64_t ax = 0;
            for(b=0; b<R->c; b++)
            {
                ax += R->v[b] * (uint64_t)h->v[a];
                if( a + b >= M->c ) break;
                ax += M->v[a + b];
                M->v[a + b] = (uint32_t)ax;
                ax >>= 32;
            }
        }

        ul = (uint32_t *)R + R->c + 1;
        t = (void *)ul;
        t->c = vlsize_modulus;

        vlong_mulv_masked(t, R, ri, 1, NULL, NULL);
        b = t->c;
        for(a=0; a<R->c; a++)
            R->v[a] = a < b ? t->v[a] : 0;
        ul = (uint32_t *)R + R->c + 1;
    
        h = (void *)ul;
        h->c = vlsize_factor;
        ul += h->c + 1;
    
        m = (void *)ul;
        m->c = vlsize_factor;
        ul += m->c + 1;
    
        t = (void *)ul;
        t->c = vlsize_factor;
        ul += t->c + 1;
    }

    return M;
}
