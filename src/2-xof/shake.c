/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#include "shake.h"
#include "../1-symm/keccak.h"

void SHAKE128_Init(shake_t *restrict x)
{
    *x = (shake_t){
        .sponge = SPONGE_INIT(200-16*2, 0x1f, 0x80, xKeccakF1600),
        .state.u64 = {0}, 
    };
}

void SHAKE256_Init(shake_t *restrict x)
{
    *x = (shake_t){
        .sponge = SPONGE_INIT(200-32*2, 0x1f, 0x80, xKeccakF1600),
        .state.u64 = {0}, 
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

IntPtr iSHAKE128(int q){ return xSHAKE128(q); }
IntPtr iSHAKE256(int q){ return xSHAKE256(q); }

IntPtr iSHAKE128o32(int q){ return xSHAKE128o32(q); }
IntPtr iSHAKE256o64(int q){ return xSHAKE256o64(q); }
