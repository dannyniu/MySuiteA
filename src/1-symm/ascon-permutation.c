/* DannyNiu/NJF, 2025-01-16. Public Domain. */

#include "ascon-permutation.h"
#include "../0-datum/endian.h"

static void P_c(uint64_t S[5], int i)
{
    int ci;
    ci = (0xf0 & ((0x3 - i) << 4)) | (0x0f & (0xc + i));
    S[2] ^= ci;
}

static void P_s(uint64_t y[restrict 5])
{
    register uint64_t u, v;

    y[0] ^= y[4];
    y[2] ^= y[1];
    y[4] ^= y[3];

    u    = y[4];
    v    = y[0];
    y[4] ^= ~y[0] & y[1];
    y[0] ^= ~y[1] & y[2];
    y[1] ^= ~y[2] & y[3];
    y[2] ^= ~y[3] & u;
    y[3] ^= ~u    & v;

    y[1] ^= y[0];
    y[3] ^= y[2];
    y[0] ^= y[4];
    y[2] = ~y[2];
}

static inline uint64_t ror(uint64_t x, int r)
{
    return (x >> r) | (x << (64 - r));
}

static void P_l(uint64_t S[5])
{
    S[0] ^= ror(S[0], 19) ^ ror(S[0], 28);
    S[1] ^= ror(S[1], 61) ^ ror(S[1], 39);
    S[2] ^= ror(S[2],  1) ^ ror(S[2],  6);
    S[3] ^= ror(S[3], 10) ^ ror(S[3], 17);
    S[4] ^= ror(S[4],  7) ^ ror(S[4], 41);
}

void Ascon_Permute(void const *in, void *out, int rounds)
{
    int i;
    uint64_t *S;
    assert( rounds > 0 && rounds <= 16 );

    S = out;
    for(i=0; i<5; i++) S[i] = le64toh( ((uint64_t *)in)[i] );

    for(i=0; i<rounds; i++)
    {
        P_c(S, 16-rounds+i);
        P_s(S);
        P_l(S);
    }

    for(i=0; i<5; i++) S[i] = htole64(S[i]);
}
