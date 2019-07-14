/* DannyNiu/NJF, 2018-02-10. Public Domain. */

#include "galois128.h"
#include "../0-datum/endian.h"

typedef struct {
    uint64_t    w[2];
} galois128_t;

static galois128_t galois128_load(const void *ptr)
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
    uint64_t x = UINT64_C(0xE100000000000000) * (Y.w[1] & 1);

    Y.w[1] = Y.w[1]>>1 | Y.w[0]<<63;
    Y.w[0] = Y.w[0]>>1 ^ x;

    return Y;
}

static galois128_t galois128_mul(galois128_t X, galois128_t Y)
{
    galois128_t Z = {0};

    for(int i=0; i<128; i++)
    {
        for(int j=0; j<2; j++)
            Z.w[j] ^=
                Y.w[j] *
                ( X.w[i/64]>>(63-i%64) & 1 );

        Y = galois128_x(Y);
    }

    return Z;
}

void galois128_hash1block(void *restrict Y,
                          const void *restrict H,
                          const void *restrict X)
{
    galois128_t y={0}, h={0}, x={0};

    if( Y ) y = galois128_load(Y);
    if( H ) h = galois128_load(H);
    if( X ) x = galois128_load(X);
    
    y.w[0] ^= x.w[0];
    y.w[1] ^= x.w[1];
    
    if( Y ) galois128_store(Y, galois128_mul(y, h));
}
