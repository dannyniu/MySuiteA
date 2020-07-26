/* DannyNiu/NJF, 2020-07-26. Public Domain. */

#include <stdint.h>

static inline uint8_t sbox(uint8_t x, uint8_t const sbox_table[256])
{
    int i;
    uint8_t ret = 0;
    uint16_t mask = 0;

    for(i=0; i<256; i++)
    {
        mask = i ^ x;
        mask = (mask - 1) >> 8;
        ret |= sbox_table[i] & mask;
    }

    return ret;
}

static inline uint8_t invsbox(uint8_t x, uint8_t const sbox_table[256])
{
    int i;
    uint8_t ret = 0;
    uint16_t mask = 0;

    for(i=0; i<256; i++)
    {
        mask = sbox_table[i] ^ x;
        mask = (mask - 1) >> 8;
        ret |= i & mask;
    }

    return ret;
}
