/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#include "../1-symm/sponge.h"
#include "../1-symm/keccak.h"
#include "shake.h"

void SHAKE128_Init(shake_t *restrict x)
{
    *x = (shake_t){
        .sponge = SPONGE_INIT(200-16*2, 0x1f, _iKeccakF1600),
        .state.u64 = {}, 
    };
}

void SHAKE256_Init(shake_t *restrict x)
{
    *x = (shake_t){
        .sponge = SPONGE_INIT(200-32*2, 0x1f, _iKeccakF1600),
        .state.u64 = {}, 
    };
}

void SHAKE_Write(shake_t *restrict x, const void *restrict data, size_t len)
{
    Sponge_Update(&x->sponge, data, len);
}

void SHAKE_Final(shake_t *restrict x)
{
    Sponge_Final(&x->sponge);
}

void SHAKE_Read(shake_t *restrict x, void *restrict data, size_t len)
{
    Sponge_Read(&x->sponge, data, len);
}

intptr_t iSHAKE128(int q){ return _iSHAKE128(q); }
intptr_t iSHAKE256(int q){ return _iSHAKE256(q); }
