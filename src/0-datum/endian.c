/* DannyNiu/NJF, 2018-01-30. Public Domain. */

#include "endian.h"

#if MySuiteA_endian_h

// Byte-Swapping Macros. 

#ifdef __ARM_ACLE

#else

uint16_t __bswap16(uint16_t x)
{
    return x >> 8 | x << 8;
}

uint32_t __bswap32(uint32_t x)
{
    static const uint32_t mask = UINT32_C(0xff00ff00);

    x = (x&mask) >> 8 | (x&~mask) << 8;
    return x >> 16 | x << 16;
}

uint64_t __bswap64(uint64_t x)
{
    static const uint64_t
        mask1 = UINT64_C(0xff00ff00ff00ff00), 
        mask2 = UINT64_C(0xffff0000ffff0000);

    x = (x&mask1) >>  8 | (x&~mask1) <<  8;
    x = (x&mask2) >> 16 | (x&~mask2) << 16;
    return x >> 32 | x << 32;
}

#endif

#endif /* MySuiteA_endian_h */
