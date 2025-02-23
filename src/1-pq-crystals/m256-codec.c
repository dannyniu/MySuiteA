/* DannyNiu/NJF, 2023-09-02. Public Domain. */

#include "m256-codec.h"

void *Module256EncU(
    uint8_t *restrict ptr, size_t len,
    module256_t const *restrict melem,
    int coeffbits)
{
    void *ret = ptr;
    uint32_t mask = (1 << coeffbits) - 1;
    uint32_t buf = 0;
    int i, filled = 0;

    for(i=0; i<256; i++)
    {
        buf |= (melem->r[i] & mask) << filled;
        filled += coeffbits;

        while( filled >= 8 )
        {
            if( !len-- ) return NULL;
            *ptr++ = (uint8_t)buf;
            buf >>= 8;
            filled -= 8;
        }
    }

    return ret;
}

void *Module256EncS(
    uint8_t *restrict ptr, size_t len,
    module256_t const *restrict melem,
    int coeffbits, int32_t shift)
{
    void *ret = ptr;
    uint32_t mask = (1 << coeffbits) - 1;
    uint32_t buf = 0;
    int i, filled = 0;

    for(i=0; i<256; i++)
    {
        buf |= ((shift - melem->r[i]) & mask) << filled;
        filled += coeffbits;

        while( filled >= 8 )
        {
            if( !len-- ) return NULL;
            *ptr++ = (uint8_t)buf;
            buf >>= 8;
            filled -= 8;
        }
    }

    return ret;
}

void *Module256DecU(
    uint8_t const *restrict ptr, size_t len,
    module256_t *restrict melem,
    int coeffbits)
{
    uint32_t mask = (1 << coeffbits) - 1;
    uint32_t buf = 0;
    int i, filled = 0;

    for(i=0; i<256; i++)
    {
        while( filled < coeffbits )
        {
            if( !len-- ) return NULL;
            buf |= (uint32_t)*ptr++ << filled;
            filled += 8;
        }

        melem->r[i] = buf & mask;
        buf >>= coeffbits;
        filled -= coeffbits;
    }

    return melem;
}

void *Module256DecS(
    uint8_t const *restrict ptr, size_t len,
    module256_t *restrict melem,
    int coeffbits, int32_t shift)
{
    uint32_t mask = (1 << coeffbits) - 1;
    uint32_t buf = 0;
    int i, filled = 0;

    for(i=0; i<256; i++)
    {
        while( filled < coeffbits )
        {
            if( !len-- ) return NULL;
            buf |= (uint32_t)*ptr++ << filled;
            filled += 8;
        }

        melem->r[i] = buf & mask;
        melem->r[i] = shift - melem->r[i];
        buf >>= coeffbits;
        filled -= coeffbits;
    }

    return melem;
}

#ifdef ENABLE_HOSTED_HEADERS

int melem_dump_dec(module256_t *melem)
{
    for(int i=0; i<256; i++)
        fprintf(stderr, "%d ", melem->r[i]);
    fprintf(stderr, "\n\n");
    return 0;
}

int melem_dump_hex(module256_t *melem)
{
    for(int i=0; i<256; i++)
        fprintf(stderr, "%x ", melem->r[i]);
    fprintf(stderr, "\n\n");
    return 0;
}

#include "../2-xof/shake.h"

int melem_dump_hashed(module256_t *melem, char *msg, int r, int s)
{
    shake_t hctx;
    uint8_t buf[8];
    SHAKE128_Init(&hctx);
    SHAKE_Write(&hctx, melem, sizeof(melem));
    SHAKE_Final(&hctx);
    SHAKE_Read(&hctx, buf, 8);
    for(int i=0; i<8; i++)
        fprintf(stderr, "%02x", buf[i]);
    fprintf(stderr, " %s", msg);
    if( r >= 0 ) fprintf(stderr, " r=%d", r);
    if( s >= 0 ) fprintf(stderr, " s=%d", s);
    fprintf(stderr, "\n");
    return 0;
}

#endif /* ENABLE_HOSTED_HEADERS */
