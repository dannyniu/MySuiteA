/* DannyNiu/NJF, 2021-10-12. Public Domain. */

#include <stddef.h>

#define DeltaTo(base, member)                                   \
    ((void *)(base ? (uint8_t *)base + base->member : NULL))

static inline void *DeltaAdd(void *base, ptrdiff_t offset)
{
    return (uint8_t *)base + offset;
}

static inline ptrdiff_t DeltaOf(void *base, void *obj)
{
    return (uint8_t *)obj - (uint8_t *)base;
}
