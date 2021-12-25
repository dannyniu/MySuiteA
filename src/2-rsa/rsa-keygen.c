/* DannyNiu/NJF, 2021-04-20. Public Domain. */

#include "rsa.h"
#include "../2-numbertheory/MillerRabin.h"
#include "../2-numbertheory/EGCD.h"
#include "../0-exec/struct-delta.c.h"

// 2021-12-25,
// The number of iterations of Miller-Rabin tests changed from 8 to 5
// per guidance in FIPS-186.
#define MR_ITERATIONS 5
#define PUB_EXPONENT 65537

#ifdef KEYGEN_LOGF_STDIO
#include <stdio.h>
#define LOGF(...) printf(__VA_ARGS__)
#else
#define LOGF(...) ((void)0)
#endif

static vlong_t *gen_oddint_bits(
    vlong_t *w, uint32_t bits, 
    GenFunc_t rng, void *restrict rng_ctx)
{
    uint32_t t, m;
    rng(rng_ctx, w->v, w->c * sizeof(uint32_t));

    for(t = bits / 32; t < w->c; t++)
    {
        if( t * 32 >= bits ) m = 0; else
        {
            m = bits - t * 32;
        }

        w->v[t] &= (1 << m) - 1;
    }

    w->v[0] |= 1;

    // 2021-12-25:
    // To avoid multiplication bit shrinking, the top of the candidate integer
    // is now or'd with 5 bits. This should be adequate when each prime factor
    // of a 15380-bit modulus (256-bit security) is at least 1024 bits, or when
    // each prime factor of a modulus of at most 7680 bits (192-bit security)
    // is at least 512 bits. 
    bits = bits - 1;
    w->v[bits / 32 - 0] |= (UINT64_C(0x1f0000000) << (bits % 32)) >> 32;
    w->v[bits / 32 - 1] |= (UINT64_C(0x1f0000000) << (bits % 32));

    return w;
}

IntPtr rsa_keygen(
    RSA_Priv_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    uint32_t bits_per_prime = param[0].aux / param[1].aux;
    uint32_t i, t;

    vlong_size_t vlsize_modulus = (param[0].aux + 32 * 2 - 1) / 32;
    vlong_size_t vlsize_factor = (bits_per_prime + 32 * 2 - 1) / 32;
    
    RSA_Priv_Base_Ctx_t *bx;
    RSA_OtherPrimeInfo_t *px;
    
    vlong_t *vl, *t1, *t2, *t3, *t4, *t5, *t6;
    uint32_t *ul;

    if( !x )
    {
        return RSA_PRIV_CTX_SIZE(param[0].aux, param[1].aux);
    }

    bx = &x->base;
    px = x->primes_other;

    bx->count_primes_other = param[1].aux - 2;
    bx->modulus_bits = param[0].aux;

restart:
    ul = DeltaAdd( 
        x,
        sizeof(RSA_Priv_Base_Ctx_t) +
        sizeof(RSA_OtherPrimeInfo_t) * bx->count_primes_other);
    
    // e -- public exponent.
    vl = (vlong_t *)ul;
    vl->c = 1;
    vl->v[0] = PUB_EXPONENT;
    bx->offset_e = DeltaOf(x, vl);
    ul += vl->c + 1;

    // p -- the first prime factor.
    vl = (vlong_t *)ul;
    vl->c = vlsize_factor;

    t1 = DeltaAdd(vl, (vl->c + 1) * 4 * 1);
    t2 = DeltaAdd(vl, (vl->c + 1) * 4 * 2);
    t3 = DeltaAdd(vl, (vl->c + 1) * 4 * 3);
    t1->c = t2->c = t3->c = vl->c;
    
    while(1)
    {
        gen_oddint_bits(vl, bits_per_prime, prng_gen, prng);
        if( MillerRabin(vl, MR_ITERATIONS, t1, t2, t3, prng_gen, prng) )
            break;
    }
    LOGF("Generated - p\n");
    
    bx->offset_p = DeltaOf(x, vl);
    ul += vl->c + 1;

    // q -- the second prime factor.
    vl = (vlong_t *)ul;
    vl->c = vlsize_factor;

    t1 = DeltaAdd(vl, (vl->c + 1) * 4 * 1);
    t2 = DeltaAdd(vl, (vl->c + 1) * 4 * 2);
    t3 = DeltaAdd(vl, (vl->c + 1) * 4 * 3);
    t1->c = t2->c = t3->c = vl->c;

    while(1)
    {
        gen_oddint_bits(vl, bits_per_prime, prng_gen, prng);
        if( MillerRabin(vl, MR_ITERATIONS, t1, t2, t3, prng_gen, prng) )
            break;
    }
    LOGF("Generated - q\n");
    
    bx->offset_q = DeltaOf(x, vl);
    ul += vl->c + 1;

    // r_i -- the i'th prime factor.
    for(t=0; t<bx->count_primes_other; t++)
    {
        vl = (vlong_t *)ul;
        vl->c = vlsize_factor;

        t1 = DeltaAdd(vl, (vl->c + 1) * 4 * 1);
        t2 = DeltaAdd(vl, (vl->c + 1) * 4 * 2);
        t3 = DeltaAdd(vl, (vl->c + 1) * 4 * 3);
        t1->c = t2->c = t3->c = vl->c;

        while(1)
        {
            gen_oddint_bits(vl, bits_per_prime, prng_gen, prng);
            if( MillerRabin(vl, MR_ITERATIONS, t1, t2, t3, prng_gen, prng) )
                break;
        }
        LOGF("Generated - r_%u\n", (unsigned)t + 3);

        px[t].offset_r = DeltaOf(x, vl);
        ul += vl->c + 1;
    }
    
    // d -- private exponent.
    vl = (vlong_t *)ul;
    vl->c = vlsize_modulus;
    
    vl->v[0] = 1;
    for(i=1; i<vl->c; i++) vl->v[i] = 0;

    // just enough space for
    // offset_w[1-4], n, and factor-sized exponents.
    t1 = DeltaAdd(vl, (vl->c + 1) * 4 * 1);
    t2 = DeltaAdd(vl, (vl->c + 1) * 4 * 2);
    t3 = DeltaAdd(vl, (vl->c + 1) * 4 * 3);
    t4 = DeltaAdd(vl, (vl->c + 1) * 4 * 4);
    t5 = DeltaAdd(vl, (vl->c + 1) * 4 * 5);
    t6 = DeltaAdd(vl, (vl->c + 1) * 4 * 6);
    t1->c = t2->c = t3->c = t4->c = t5->c = t6->c = vl->c;

    // -- mult (p - 1) --
    vlong_adds(
        DeltaTo(bx, offset_p),
        DeltaTo(bx, offset_p),
        -1, 0);
    vlong_mulv_masked(
        t1, vl, DeltaTo(bx, offset_p),
        1, NULL, NULL);
    vlong_adds(
        DeltaTo(bx, offset_p),
        DeltaTo(bx, offset_p),
        +1, 0);
    for(i=0; i<vl->c; i++) vl->v[i] = t1->v[i];
    
    LOGF("Computing - d - mult (p - 1)\n");

    // -- mult (q - 1) --
    vlong_adds(
        DeltaTo(bx, offset_q),
        DeltaTo(bx, offset_q),
        -1, 0);
    vlong_mulv_masked(
        t1, vl, DeltaTo(bx, offset_q),
        1, NULL, NULL);
    vlong_adds(
        DeltaTo(bx, offset_q),
        DeltaTo(bx, offset_q),
        +1, 0);
    for(i=0; i<vl->c; i++) vl->v[i] = t1->v[i];
    
    LOGF("Computing - d - mult (q - 1)\n");

    // -- mult (r_i - 1) --
    for(t=0; t<bx->count_primes_other; t++)
    {
        vlong_adds(
            DeltaAdd(bx, px[t].offset_r),
            DeltaAdd(bx, px[t].offset_r),
            -1, 0);
        vlong_mulv_masked(
            t1, vl, DeltaAdd(bx, px[t].offset_r),
            1, NULL, NULL);
        vlong_adds(
            DeltaAdd(bx, px[t].offset_r),
            DeltaAdd(bx, px[t].offset_r),
            +1, 0);
        for(i=0; i<vl->c; i++) vl->v[i] = t1->v[i];
        
        LOGF("Computing - d - mult (r_%u - 1)\n", (unsigned)t + 3);
    }

    // -- copy e --
    t5->v[0] = PUB_EXPONENT;
    for(i=1; i<t1->c; i++) t5->v[i] = 0;
    
    // -- copy \lambda(n) --
    for(i=0; i<t6->c; i++) t6->v[i] = vl->v[i];

    // -- EGCD: e^{-1} mod \lambda(n) --
    t5 = EGCD(t5, vl, t1, t2, t3, t4);
    if( !t5 )
    {
        LOGF("EGCD on e and lambda{n} failed, restarting\n");
        goto restart;
    }
    for(i=0; i<vl->c; i++) vl->v[i] = t5->v[i];
    vlong_imod_inplace(vl, t6);
    
    bx->offset_d = DeltaOf(x, vl);
    ul += vl->c + 1;

    LOGF("Computed - d\n");

    // n -- allocated early to hold R_i for computing t_i.
    vl = (vlong_t *)ul;
    vl->c = vlsize_modulus;
    ul += vl->c + 1;

    // qInv, t_i -- CRT coefficient.
    t6 = vl;
    
    for(i=0; i<t6->c; i++)
        t6->v[i] = 0;
    
    for(i=0; i<vlsize_factor; i++)
        t6->v[i] = ((vlong_t *)DeltaTo(bx, offset_q))->v[i];

    for(t=0; t<bx->count_primes_other+1; t++)
    {
        vl = (vlong_t *)ul;
        vl->c = vlsize_factor;

        t1 = DeltaAdd(vl, (vl->c + 1) * 4 * 1);
        t2 = DeltaAdd(vl, (vl->c + 1) * 4 * 2);
        t3 = DeltaAdd(vl, (vl->c + 1) * 4 * 3);
        t4 = DeltaAdd(vl, (vl->c + 1) * 4 * 4);
        t1->c = t2->c = t3->c = vl->c;
        t4->c = t6->c;

        vlong_divv(
            vl, NULL, t6, // 2021-09-11: typo, was t4, should be t6.
            DeltaAdd(bx, px[(int32_t)t - 1].offset_r));

        vlong_adds(
            t1,
            DeltaAdd(bx, px[(int32_t)t - 1].offset_r),
            -2, 0);

        // 2021-07-27:
        // this is probably the original reason
        // for the [2021-06-05] change in "1-integers/vlong.c".
        vlong_modexpv(
            vl, vl, t1, t2, t3,
            (vlong_modfunc_t)vlong_remv_inplace,
            (void *)DeltaAdd(bx, px[(int32_t)t - 1].offset_r));

        px[(int32_t)t - 1].offset_t = DeltaOf(x, vl);
        ul += vl->c + 1;

        LOGF("Computed - t_%u\n", t + 2);

        // -- n: accumulate to the public modulus --
        vlong_mulv_masked(
            t4, t6, DeltaAdd(bx, px[(int32_t)t - 1].offset_r),
            1, NULL, NULL);

        for(i=0; i<t6->c; i++) t6->v[i] = t4->v[i];

        // -- check if modulus shrinked due to low parity at high bits. --
        i = bits_per_prime * (t + 2) - 1;
        if( t6->v[i / 32] >> (i % 32) == 0 )
        {
            LOGF("Higher-order bits shrinked, restarting\n");
            goto restart;
        }
    }

    bx->offset_n = DeltaOf(bx, t6);

    // dP -- CRT exponent of p.
    vl = (vlong_t *)ul;
    vl->c = vlsize_factor;

    vlong_adds(
        DeltaTo(bx, offset_p),
        DeltaTo(bx, offset_p),
        -1, 0);
    vlong_divv(
        vl, NULL,
        DeltaTo(bx, offset_d),
        DeltaTo(bx, offset_p));
    vlong_adds(
        DeltaTo(bx, offset_p),
        DeltaTo(bx, offset_p),
        +1, 0);

    bx->offset_dP = DeltaOf(x, vl);
    ul += vl->c + 1;

    LOGF("Computed - dP\n");

    // dQ -- CRT exponent of q.
    vl = (vlong_t *)ul;
    vl->c = vlsize_factor;
    
    vlong_adds(
        DeltaTo(bx, offset_q),
        DeltaTo(bx, offset_q),
        -1, 0);
    vlong_divv(
        vl, NULL,
        DeltaTo(bx, offset_d),
        DeltaTo(bx, offset_q));
    vlong_adds(
        DeltaTo(bx, offset_q),
        DeltaTo(bx, offset_q),
        +1, 0);

    bx->offset_dQ = DeltaOf(x, vl);
    ul += vl->c + 1;

    LOGF("Computed - dQ\n");

    // d_i -- additional CRT exponents.
    for(t=0; t<bx->count_primes_other; t++)
    {
        vl = (vlong_t *)ul;
        vl->c = vlsize_factor;
    
        vlong_adds(
            DeltaAdd(bx, px[t].offset_r),
            DeltaAdd(bx, px[t].offset_r),
            -1, 0);
        vlong_divv(
            vl, NULL,
            DeltaTo(bx, offset_d),
            DeltaAdd(bx, px[t].offset_r));
        vlong_adds(
            DeltaAdd(bx, px[t].offset_r),
            DeltaAdd(bx, px[t].offset_r),
            +1, 0);

        px[t].offset_d = DeltaOf(x, vl);
        ul += vl->c + 1;

        LOGF("Computed - d_%u\n", (unsigned)t + 3);
    }

    // working variables:
    vl = (vlong_t *)ul;
    vl->c = vlsize_modulus;
    
    bx->offset_w1 = DeltaOf(x, vl);
    ul += vl->c + 1;

    vl = (vlong_t *)ul;
    vl->c = vlsize_modulus;
    
    bx->offset_w2 = DeltaOf(x, vl);
    ul += vl->c + 1;

    vl = (vlong_t *)ul;
    vl->c = vlsize_modulus;
    
    bx->offset_w3 = DeltaOf(x, vl);
    ul += vl->c + 1;

    vl = (vlong_t *)ul;
    vl->c = vlsize_modulus;
    
    bx->offset_w4 = DeltaOf(x, vl);
    ul += vl->c + 1;

    vl = (vlong_t *)ul;
    vl->c = vlsize_modulus;
    
    bx->offset_w5 = DeltaOf(x, vl);
    ul += vl->c + 1;

    for(i=0; i<vlsize_modulus; i++)
    {
        ((vlong_t *)DeltaTo(bx, offset_w1))->v[i] = 0;
        ((vlong_t *)DeltaTo(bx, offset_w2))->v[i] = 0;
        ((vlong_t *)DeltaTo(bx, offset_w3))->v[i] = 0;
        ((vlong_t *)DeltaTo(bx, offset_w4))->v[i] = 0;
        ((vlong_t *)DeltaTo(bx, offset_w5))->v[i] = 0;
    }

    LOGF("Total Size: %tu\n", DeltaOf(x, ul));
    return (IntPtr)x;
}
