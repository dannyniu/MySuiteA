/* DannyNiu/NJF, 2021-09-03. Public Domain. */

#include "vlong-dat.h"

vlong_size_t vlong_topbit(vlong_t *x)
{
    vlong_size_t i;
    uint32_t bits;

    for(i=x->c; --i; )
        if( x->v[i] ) break;

    bits = x->v[i];
    i = i * 32;
    while( bits ) i++, bits >>= 1;
    return i;
}

void vlong_OS2IP(vlong_t *restrict vl, const uint8_t *restrict os, size_t len)
{
    // 2021-09-11:
    // This function is being tested through RSA-OAEP cipher,
    // currently passing self-feeding tests, but not ones using
    // publicly available test vectors.

    vlong_size_t i;

    static_assert(
        sizeof(*vl->v) == 4 && sizeof(uint32_t) == 4,
        "Data type assumption failed.");

    for(i=0; i<vl->c; i++) vl->v[i] = 0;

    for(i=0; i<len; i++)
    {
        if( i >= vl->c * 4 ) break;
        vl->v[i / 4] |= (uint32_t)os[len - i - 1] << (i * 8 % 32);
    }
}

void vlong_I2OSP(vlong_t const *restrict vl, uint8_t *restrict os, size_t len)
{
    // 2021-09-11:
    // This function is being tested through RSA-OAEP cipher,
    // currently passing self-feeding tests, but not ones using
    // publicly available test vectors.

    vlong_size_t i;

    static_assert(
        sizeof(*vl->v) == 4 && sizeof(uint32_t) == 4,
        "Data type assumption failed.");

    for(i=0; i<len; i++) os[i] = 0;

    for(i=0; i<len; i++)
    {
        if( i >= vl->c * 4 ) break;
        os[len - i - 1] = vl->v[i / 4] >> (i * 8 % 32);
    }
}

void vlong_EncLSB(vlong_t const *restrict vl, uint8_t *restrict os, size_t len)
{
    vlong_size_t i;

    static_assert(
        sizeof(*vl->v) == 4 && sizeof(uint32_t) == 4,
        "Data type assumption failed.");

    for(i=0; i<len; i++) os[i] = 0;
    for(i=0; i<len; i++)
    {
        if( i >= vl->c * 4 ) break;
        os[i] = vl->v[i / 4] >> (i * 8 % 32);
    }
}

void vlong_DecLSB(vlong_t *restrict vl, const uint8_t *restrict os, size_t len)
{
    vlong_size_t i;

    static_assert(
        sizeof(*vl->v) == 4 && sizeof(uint32_t) == 4,
        "Data type assumption failed.");

    for(i=0; i<vl->c; i++) vl->v[i] = 0;

    for(i=0; i<len; i++)
    {
        if( i >= vl->c * 4 ) break;
        vl->v[i / 4] |= (uint32_t)os[i] << (i * 8 % 32);
    }
}
