/* DannyNiu/NJF, 2023-10-23. Public Domain. */

#include "kyber-aux.h"
#include "../1-pq-crystals/m256-codec.h"
#include "../2-xof/shake.h"

void MLKEM_SampleNTT(
    module256_t *restrict melem,
    uint8_t const rho[restrict 32],
    int i, int j)
{
    uint8_t c[3];
    int d1, d2;

    shake128_t hctx;

    assert( 0 <= i && i < 4 && 0 <= j && j < 4 );

    SHAKE128_Init(&hctx);
    SHAKE_Write(&hctx, rho, 32);
    c[0] = j;
    c[1] = i;
    SHAKE_Write(&hctx, c, 2);
    SHAKE_Final(&hctx);

    // reusing argument as local variable.
    i = j = 0;

    while( j < 256 )
    {
        SHAKE_Read(&hctx, c, 3);
        d1 = c[0] + ((c[1] & 15) << 8);
        d2 = (c[1] >> 4) + (c[2] << 4);

        if( d1 < MLKEM_Q )
            melem->r[j++] = d1;

        if( d2 < MLKEM_Q && j < 256 )
            melem->r[j++] = d2;
    }
}

static void MLKEM_SamplePolyCBD_TRNG(
    module256_t *restrict melem,
    GenFunc_t prng_gen, void *restrict prng, int eta)
{
    uint8_t c;
    uint32_t buf = 0;
    int filled = 0;
    int i, j;
    int x, y;

    for(i=0; i<256; i++)
    {
        while( filled < eta * 2 )
        {
            prng_gen(prng, &c, 1);
            buf |= (uint32_t)c << filled;
            filled += 8;
        }

        for(x=y=j=0; j<eta; j++)
        {
            x += 1 & (buf >> j);
            y += 1 & (buf >> (j + eta));
        }

        buf >>= eta * 2;
        filled -= eta * 2;

        melem->r[i] = MLKEM_UModQ(x - y);
    }
}

void MLKEM_SamplePolyCBD(
    module256_t *restrict melem,
    uint8_t const rho[restrict 32],
    int n, int eta)
{
    uint8_t c;

    shake256_t hctx;

    SHAKE256_Init(&hctx);
    SHAKE_Write(&hctx, rho, 32);
    c = n;
    SHAKE_Write(&hctx, &c, 1);
    SHAKE_Final(&hctx);

    MLKEM_SamplePolyCBD_TRNG(melem, (GenFunc_t)SHAKE_Read, &hctx, eta);
}

int32_t MLKEM_UModQ(int32_t r) // unsigned modular reduction.
{
    // based on: https://crypto.stackexchange.com/a/88237/36960
    uint32_t x = r;
    uint32_t s = x;

    s = -(s >> 31);
    x ^= s;

    x -= (x >> 12) * MLKEM_Q;
    x -= (x >> 12) * MLKEM_Q;
    x -= (x >> 12) * MLKEM_Q;
    x -= (x >> 12) * MLKEM_Q;
    x -= (x >> 12) * MLKEM_Q;
    x -= -((MLKEM_Q - x - 1) >> 31) & MLKEM_Q;

    x ^= ((MLKEM_Q - 1 - x) ^ x) & s;
    return x; // 2023-10-23: this function has been adapted for kyber.
}

module256_t *MLKEM_Add(
    module256_t *c,
    module256_t *a,
    module256_t *b,
    int accum)
{
    int i;

    if( accum )
    {
        for(i=0; i<256; i++)
        {
            c->r[i] = MLKEM_UModQ(c->r[i] + a->r[i] + b->r[i]);
        }
    }
    else
    {
        for(i=0; i<256; i++)
            c->r[i] = MLKEM_UModQ(a->r[i] + b->r[i]);
    }

    return c;
}

module256_t *MLKEM_Sub(
    module256_t *c,
    module256_t *a,
    module256_t *b)
{
    int i;

    for(i=0; i<256; i++)
        c->r[i] = MLKEM_UModQ(a->r[i] - b->r[i]);

    return c;
}

static const int32_t zetas[256];

module256_t *MLKEM_NttScl(
    module256_t *c,
    module256_t *a,
    module256_t *b,
    int accum)
{
    int i;
    int32_t c1, c2, gamma;

    for(i=0; i<256; i+=2)
    {
        gamma = zetas[i/2];
        gamma = gamma * gamma % MLKEM_Q;
        gamma = gamma * 17 % MLKEM_Q;

        c1  = MLKEM_UModQ(a->r[i+1] * b->r[i+1]);
        c1  = MLKEM_UModQ(c1 * gamma);
        c1 += MLKEM_UModQ(a->r[i] * b->r[i]);
        c1  = MLKEM_UModQ(c1);

        c2  = MLKEM_UModQ(a->r[i] * b->r[i+1]);
        c2 += MLKEM_UModQ(a->r[i+1] * b->r[i]);
        c2  = MLKEM_UModQ(c2);

        if( accum )
        {
            c->r[i+0] += c1;
            c->r[i+1] += c2;
            c->r[i+0] = MLKEM_UModQ(c->r[i+0]);
            c->r[i+1] = MLKEM_UModQ(c->r[i+1]);
        }
        else
        {
            c->r[i] = c1;
            c->r[i+1] = c2;
        }
    }

    return c;
}

static int32_t iCompressToM(int32_t x)
{
    // 2023-12-23:
    // There's a thread on the NIST PQC forum started by DJB
    // showing some of the divisions by Q is not safe from
    // a side channel perspective. The way ``Compress'' used
    // is side-channel-safe in K-PKE.Encrypt, but not so
    // in K-PKE.Decrypt, when applied to 'm'.
    // This function is the fix for it.

    // 2023-12-23: Assume 0 <= x < MLKEM_Q
    x <<= 1;
    x += MLKEM_Q / 2;
    x = ((MLKEM_Q - x) >> 31) & ((x - 2*MLKEM_Q) >> 31);
    return x & 1;
}

static int32_t iCompress(int32_t x, int d)
{
    x <<= d;

    // Compress is always executed on values that can be made public.
    // Side channel protection isn't urgent.
    x += MLKEM_Q / 2;
    x /= MLKEM_Q;
    x &= ((uint32_t)1 << d) -1;

    return x;
}

static int32_t iDecompress(int32_t x, int d)
{
    x *= MLKEM_Q;

    // 2023-11-19:
    // This was added when testing against the example values provided by NIST.
    x += 1 << (d - 1);

    x >>= d;

    return x;
}

void MLKEM_CompressToM(module256_t *m)
{
    int i;

    for(i=0; i<256; i++) m->r[i] = iCompressToM(m->r[i]);
}

void MLKEM_Compress(module256_t *m, int d)
{
    int i;

    for(i=0; i<256; i++) m->r[i] = iCompress(m->r[i], d);
}

void MLKEM_Decompress(module256_t *m, int d)
{
    int i;

    for(i=0; i<256; i++) m->r[i] = iDecompress(m->r[i], d);
}

static const int32_t zetas[256] = {
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
};

void MLKEM_NTT(module256_t *restrict melem)
{
    int len, start, j, k;
    int32_t t;
    int32_t *a = melem->r;
    int32_t zeta;

    k = 1;
    for(len = 128; len >= 2; len >>= 1) {
        for(start = 0; start < 256; start += 2 * len) {
            zeta = zetas[k++];
            for(j = start; j < start + len; ++j) {
                t = MLKEM_UModQ(zeta * a[j + len]);
                a[j + len] = MLKEM_UModQ(a[j] - t);
                a[j] = MLKEM_UModQ(a[j] + t);
            }
        }
    }
}

void MLKEM_InvNTT(module256_t *restrict melem)
{
    int start, len, j, k;
    int32_t t;
    int32_t *a = melem->r;
    int32_t zeta;

    const int32_t f = 3303; // 128^{-1} mod q

    k = 127;
    for(len = 2; len <= 128; len <<= 1) {
        for(start = 0; start < 256; start += 2 * len) {
            zeta = zetas[k--];
            for(j = start; j < start + len; ++j) {
                t = a[j];
                a[j] = MLKEM_UModQ(t + a[j + len]);
                a[j + len] = MLKEM_UModQ(a[j + len] - t);
                a[j + len] = MLKEM_UModQ(a[j + len] * zeta);
            }
        }
    }

    for(j = 0; j < 256; ++j) {
        a[j] = MLKEM_UModQ(f * a[j]);
    }
}
