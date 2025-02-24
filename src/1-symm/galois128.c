/* DannyNiu/NJF, 2018-02-10. Public Domain. */

#include "galois128.h"

// see 2025-02-23 note towards the beginning of "1-symm/rijndael.c".
#if defined(DEF_INC_FROM_NI) == defined(IntrinSelf)

#include "../0-datum/endian.h"

typedef struct {
    uint64_t    w[2];
} galois128_t;

static galois128_t galois128_load(void const *ptr)
{
    galois128_t ret = (galois128_t){
        .w[0] = be64toh( ((const uint64_t *)ptr)[0] ),
        .w[1] = be64toh( ((const uint64_t *)ptr)[1] ),
    };
    return ret;
}

static void galois128_store(void *ptr, galois128_t v)
{
    uint64_t *w = ptr;
    w[0] = htobe64(v.w[0]);
    w[1] = htobe64(v.w[1]);
}

static galois128_t galois128_x(galois128_t Y)
{
    register uint64_t mask, x;
    mask = Y.w[1] & 1;
    mask = ~(mask - 1);
    x = UINT64_C(0xE100000000000000) & mask;

    Y.w[1] = Y.w[1]>>1 | Y.w[0]<<63;
    Y.w[0] = Y.w[0]>>1 ^ x;

    return Y;
}

static galois128_t galois128_mul(galois128_t X, galois128_t Y)
{
    galois128_t Z = {0};
    int i, j;

    for(i=0; i<128; i++)
    {
        register uint64_t mask;
        mask = X.w[i/64] >> (63 - (i & 63));
        mask &= 1;
        mask = ~(mask - 1);
        for(j=0; j<2; j++)
            Z.w[j] ^= Y.w[j] & mask;

        Y = galois128_x(Y);
    }

    return Z;
}

void galois128_hash1block_ci(
    void *restrict Y,
    void const *restrict H,
    void const *restrict X)
{
    galois128_t y={0}, h={0}, x={0};

    if( Y ) y = galois128_load(Y);
    if( H ) h = galois128_load(H);
    if( X ) x = galois128_load(X);

    y.w[0] ^= x.w[0];
    y.w[1] ^= x.w[1];

    if( Y ) galois128_store(Y, galois128_mul(y, h));
}

#if NI_GALOIS128 == NI_RUNTIME
int extern_ni_galois128_conf = false;
#endif /* NI_GALOIS128 */

#endif /* duplicate symbol definitions guard. */
