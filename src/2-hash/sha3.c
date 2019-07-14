/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#include "../1-symm/sponge.h"
#include "../1-symm/keccak.h"
#include "sha3.h"

#define Define_SHA3_Init(name,rate)                                     \
    void name(sha3_t *restrict x)                                       \
    {                                                                   \
        *x = (sha3_t){                                                  \
            .sponge = SPONGE_INIT(rate, 0x06, _iKeccakF1600),           \
            .state.u64 = {0},                                           \
        };                                                              \
    }
Define_SHA3_Init(SHA3_224_Init, 200-28*2)
Define_SHA3_Init(SHA3_256_Init, 200-32*2)
Define_SHA3_Init(SHA3_384_Init, 200-48*2)
Define_SHA3_Init(SHA3_512_Init, 200-64*2)

void SHA3_Update(sha3_t *restrict x, const void *restrict data, size_t len)
{
    Sponge_Update(&x->sponge, data, len);
}

#define Define_SHA3_Final(name,out_len)                     \
    void name(sha3_t *restrict x, void *restrict out)       \
    {                                                       \
        Sponge_Final(&x->sponge);                           \
        for(int i=0; i<out_len; i++)                        \
            ((uint8_t *)out)[i] = x->state.u8[i];           \
    }
Define_SHA3_Final(SHA3_224_Final, 28)
Define_SHA3_Final(SHA3_256_Final, 32)
Define_SHA3_Final(SHA3_384_Final, 48)
Define_SHA3_Final(SHA3_512_Final, 64)

uintptr_t iSHA3_224(int q){ return _iSHA3(224,q); }
uintptr_t iSHA3_256(int q){ return _iSHA3(256,q); }
uintptr_t iSHA3_384(int q){ return _iSHA3(384,q); }
uintptr_t iSHA3_512(int q){ return _iSHA3(512,q); }
