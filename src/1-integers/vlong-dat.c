/* DannyNiu/NJF, 2021-09-03. Public Domain. */

#include "vlong-dat.h"

static_assert(
    sizeof(*vl->v) == 4 && sizeof(uint32_t) == 4,
    "Data type assumption failed.");

void vlong_OS2IP(vlong_t *restrict vl, const uint8_t *restrict os, size_t len)
{
    // 2021-09-03: This function had not been tested yet //
    vlong_size_t i;

    for(i=0; i<vl->c; i++) vl->v[i] = 0;

    for(i=0; i<len; i++)
    {
        if( i / 4 > vl->c ) break;
        vl->v[i / 4] |= (uint32_t)os[len - i - 1] << (i % 4);
    }
}

void vlong_I2OSP(vlong_t const *restrict vl, uint8_t *restrict os, size_t len)
{
    // 2021-09-03: This function had not been tested yet //
    vlong_size_t i;

    for(i=0; i<len; i++) os[i] = 0;

    for(i=0; i<len; i++)
    {
        if( i / 4 > vl->c ) break;
        os[len - i - 1] = vl->v[i / 4] >> (i * 8 % 32);
    }
}
