/* DannyNiu/NJF, 2018-04-20. Public Domain. */

// Adapted from: 
// "https://github.com/peterferrie/gimli/blob/master/c-ref/gimli.c"

#include "gimli.h"
#include "../0-datum/endian.h"

static inline uint32_t rotate(uint32_t x, int bits)
{
    if (bits == 0) return x;
    return (x << bits) | (x >> (32 - bits));
}

static void gimli(uint32_t *state)
{
    unsigned round;
    unsigned column;
    uint32_t x;
    uint32_t y;
    uint32_t z;

    for (round = 24; round > 0; --round)
    {
        for (column = 0; column < 4; ++column)
        {
            x = rotate(state[    column], 24);
            y = rotate(state[4 + column],  9);
            z =        state[8 + column];

            state[8 + column] = x ^ (z << 1) ^ ((y&z) << 2);
            state[4 + column] = y ^ x        ^ ((x|z) << 1);
            state[column]     = z ^ y        ^ ((x&y) << 3);
        }

        if ((round & 3) == 0) { // small swap: pattern s...s...s... etc.
            x = state[0];
            state[0] = state[1];
            state[1] = x;
            x = state[2];
            state[2] = state[3];
            state[3] = x;
        }
        if ((round & 3) == 2) { // big swap: pattern ..S...S...S. etc.
            x = state[0];
            state[0] = state[2];
            state[2] = x;
            x = state[1];
            state[1] = state[3];
            state[3] = x;
        }

        if ((round & 3) == 0) { // add constant: pattern c...c...c... etc.
            state[0] ^= (0x9e377900 | round);
        }
    }
}

void Gimli_Permute(void const *in, void *out)
{
    int i;

    for(i=0; i<12; i++) {
        ((uint32_t *)out)[i] = le32toh( ((const uint32_t *)in)[i] );
    }
    gimli(out);
    for(i=0; i<12; i++) {
        ((uint32_t *)out)[i] = htole32( ((const uint32_t *)out)[i] );
    }
}

IntPtr iGimli(int q)
{
    return xGimli(q);
}
