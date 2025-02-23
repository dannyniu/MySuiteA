/* DannyNiu/NJF, 2023-09-02. Public Domain. */

#include "dilithium-aux.h"
#include "../1-pq-crystals/m256-codec.h"
#include "../2-xof/shake.h"

void MLDSA_RejNTTPoly(
    module256_t *restrict melem,
    uint8_t const rho[restrict 32],
    int s, int r)
{
    uint8_t c[3];
    int j = 0;

    shake128_t hctx;

    assert( 0 <= s && s < 7 && 0 <= r && r < 8 );

    SHAKE128_Init(&hctx);
    SHAKE_Write(&hctx, rho, 32);
    c[0] = s;
    c[1] = r;
    SHAKE_Write(&hctx, c, 2);
    SHAKE_Final(&hctx);

    while( j < 256 )
    {
        SHAKE_Read(&hctx, c, 3);
        c[2] &= 127;
        melem->r[j] = (uint32_t)c[2] << 16 | (uint32_t)c[1] << 8 | c[0];
        if( melem->r[j] < MLDSA_Q ) j++;
    }
}

static inline int CoeffFromNibble(int b, int eta)
{
    if( eta == 2 && b < 15 )
    {
        return 2 - b % 5;
    }
    else
    {
        if( eta == 4 && b < 9 ) return 4 - b;
        else return eta + 1;
    }
}

void MLDSA_RejBoundedPoly_TRNG(
    module256_t *restrict melem,
    GenFunc_t prng_gen, void *restrict prng, int eta)
{
    uint8_t c[2];
    int j = 0;
    int z0, z1;

    while( j < 256 )
    {
        prng_gen(prng, c, 1);
        c[1] = c[0] >> 4;
        c[0] &= 0x0f;

        z0 = CoeffFromNibble(c[0], eta);
        z1 = CoeffFromNibble(c[1], eta);

        if( z0 <= eta )
            melem->r[j++] = z0;

        if( z1 <= eta && j < 256 )
            melem->r[j++] = z1;
    }
}

void MLDSA_RejBoundedPoly(
    module256_t *restrict melem,
    uint8_t const rho[restrict 64],
    int r, int eta)
{
    uint8_t c[2];

    shake256_t hctx;

    assert( 0 <= r && r < 8+7 );

    SHAKE256_Init(&hctx);
    SHAKE_Write(&hctx, rho, 64);
    c[0] = (uint8_t)r;
    c[1] = (uint8_t)(r >> 8);
    SHAKE_Write(&hctx, c, 2);
    SHAKE_Final(&hctx);

    MLDSA_RejBoundedPoly_TRNG(melem, (GenFunc_t)SHAKE_Read, &hctx, eta);
}

void MLDSA_ExpandMask_1Poly_TRNG(
    module256_t *restrict melem,
    GenFunc_t prng_gen, void *restrict prng,
    int l2gamma)
{
    uint8_t v[640];
    prng_gen(prng, v, (l2gamma+1)*32);
    Module256DecS(v, (l2gamma+1)*32, melem, l2gamma+1, 1<<l2gamma);
}

void MLDSA_ExpandMask_1Poly(
    module256_t *restrict melem,
    uint8_t const rho[restrict 64],
    int r, int l2gamma, int kappa)
{
    // As noted by Vadim Lyubashevsky on his
    // Fri, 8 Sep 2023 14:14:42 +0200 message
    // on the PQC list, (as well as mine more
    // recently,) this subroutine is currently
    // specified sub-optimally. This prevents
    // any further testing beyond the basic
    // self-consistency check.
    //
    // The README file from the test vectors
    // provided by NIST on Oct 2023 says that
    // the output should be read off the front,
    // thus serving as an errata for the draft.
    //
    // 2024-08-20:
    // According to the standard published not long ago,
    // the current MySuiteA implementation is conformant.
    uint8_t v[2];
    uint16_t n = r + kappa;
    shake256_t hctx;

    v[0] = (uint8_t)(n & 0xff);
    v[1] = (uint8_t)(n >> 8);

    SHAKE256_Init(&hctx);
    SHAKE_Write(&hctx, rho ,64);
    SHAKE_Write(&hctx, v, 2);
    SHAKE_Final(&hctx);

    MLDSA_ExpandMask_1Poly_TRNG(
        melem, (GenFunc_t)SHAKE_Read, &hctx, l2gamma);
}

int64_t MLDSA_UModQ(int64_t r) // unsigned modular reduction.
{
    // based on: https://crypto.stackexchange.com/a/88237/36960
    uint64_t x = r;
    uint64_t s = x;

    s = -(s >> 63);
    x ^= s;

    x -= (x >> 23) * MLDSA_Q;
    x -= (x >> 23) * MLDSA_Q;
    x -= (x >> 23) * MLDSA_Q;
    x -= -((MLDSA_Q - x - 1) >> 63) & MLDSA_Q;

    x ^= ((MLDSA_Q - 1 - x) ^ x) & s;
    return x;
}

module256_t *MLDSA_Add(
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
            c->r[i] = MLDSA_UModQ(
                (int64_t)c->r[i] + a->r[i] + b->r[i]);
        }
    }
    else
    {
        for(i=0; i<256; i++)
            c->r[i] = MLDSA_UModQ((int64_t)a->r[i] + b->r[i]);
    }

    return c;
}

module256_t *MLDSA_Sub(
    module256_t *c,
    module256_t *a,
    module256_t *b)
{
    int i;

    for(i=0; i<256; i++)
        c->r[i] = MLDSA_UModQ((int64_t)a->r[i] - b->r[i]);

    return c;
}

module256_t *MLDSA_NttScl(
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
            c->r[i] = MLDSA_UModQ(
                MLDSA_UModQ((int64_t)a->r[i] * b->r[i]) + c->r[i]);
        }
    }
    else
    {
        for(i=0; i<256; i++)
            c->r[i] = MLDSA_UModQ((int64_t)a->r[i] * b->r[i]);
    }

    return c;
}

bool MLDSA_HasOverflow(module256_t *m, int32_t bound)
{
    uint64_t max = bound * 2 - 1;
    uint64_t shift = bound - 1;
    int i;

    for(i=0; i<256; i++)
    {
        if( (uint64_t)MLDSA_UModQ((int64_t)m->r[i] + shift) >= max )
            return true;
    }

    return false;
}

int32_t MLDSA_Power2Round(int32_t a, int32_t *a0, int d)
{
    // 2024-09-01:
    // now verbatim of that of the reference implementation.
    int32_t a1;

    a1 = (a + (1 << (d-1)) - 1) >> d;

    if( a0 ) *a0 = a - (a1 << d);
    return a1;
}

int32_t MLDSA_Decompose(int32_t r, int32_t *r0_out, int32_t gamma2)
{
    // (mostly) verbatim from:
    // https://github.com/pq-crystals/dilithium/blob/master/ref/rounding.c

    int32_t a = r;
    int32_t a1;
    int32_t a0;

    a1  = (a + 127) >> 7;
    if( gamma2 == (MLDSA_Q-1)/32 )
    {
        a1  = (a1*1025 + ((int32_t)1 << 21)) >> 22;
        a1 &= 15;
    }
    else if( gamma2 == (MLDSA_Q-1)/88 )
    {
        a1  = (a1*11275 + ((int32_t)1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }

    if( r0_out )
    {
        a0  = a - a1*2*gamma2;
        a0 -= (((MLDSA_Q-1)/2 - a0) >> 31) & MLDSA_Q;
        *r0_out = a0;
    }

    return a1;
}

int MLDSA_MakeHint(int32_t z, int32_t r, int32_t gamma2)
{
    int32_t r1, v1;
    r1 = MLDSA_UModQ(r);
    v1 = MLDSA_UModQ(r + z);
    r1 = MLDSA_Decompose(r1, NULL, gamma2);// 95232 for MLDSA-44
    v1 = MLDSA_Decompose(v1, NULL, gamma2);

    r1 ^= v1;
    r1 |= r1 >> 16;
    r1 |= r1 >> 8;
    r1 |= r1 >> 4;
    r1 |= r1 >> 2;
    r1 |= r1 >> 1;
    return r1 & 1;
}

int32_t MLDSA_UseHint(int32_t r, int h, int32_t gamma2)
{
    // This function is used only in verification function,
    // so it doesn't strictly need to be side-channel-resistant.
    uint32_t m = (MLDSA_Q - 1) / (2 * gamma2);
    int32_t r1, r0;

    r1 = MLDSA_Decompose(r, &r0, gamma2);

    if( h )
    {
        if( r0 >  0 ) r1 += 1;
        if( r0 <= 0 ) r1 -= 1;
    }

    while( r1 < 0 ) r1 += m;
    return r1 % m;
}

static const int32_t zetas[256] = {
    1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
    7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240,
    5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481,
    5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
    3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
    394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
    3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
    5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416,
    3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
    2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
    1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034,
    4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457,
    5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
    7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250,
    1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
    348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
    1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
    1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471,
    8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
    6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040,
    4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
    3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
    2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950,
    7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
    6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006,
    6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891,
    5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667,
    3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
    3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976,
    3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265,
    6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
    8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
};

void MLDSA_NTT(module256_t *restrict melem)
{
    int len, start, j, k;
    int32_t t;
    int32_t *a = melem->r;
    int64_t zeta;

    k = 0;
    for(len = 128; len > 0; len >>= 1) {
        for(start = 0; start < 256; start = j + len) {
            zeta = zetas[++k];
            for(j = start; j < start + len; ++j) {
                t = MLDSA_UModQ(zeta * a[j + len]);
                a[j + len] = MLDSA_UModQ(a[j] - t);
                a[j] = MLDSA_UModQ(a[j] + t);
            }
        }
    }
}

void MLDSA_InvNTT(module256_t *restrict melem)
{
    int start, len, j, k;
    int32_t t;
    int32_t *a = melem->r;
    int64_t zeta;

    const int64_t f = 8347681; // 256^{-1} mod q

    k = 256;
    for(len = 1; len < 256; len <<= 1) {
        for(start = 0; start < 256; start = j + len) {
            zeta = -zetas[--k];
            for(j = start; j < start + len; ++j) {
                t = a[j];
                a[j] = MLDSA_UModQ(t + a[j + len]);
                a[j + len] = MLDSA_UModQ(t - a[j + len]);
                a[j + len] = MLDSA_UModQ(zeta * a[j + len]);
            }
        }
    }

    for(j = 0; j < 256; ++j) {
        a[j] = MLDSA_UModQ(f * a[j]);
    }
}
