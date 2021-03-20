/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#include "../1-symm/gimli.h"
#include "gimli-xof.h"

void Gimli_XOF_Init(gimli_xof_t *restrict x)
{
    *x = (gimli_xof_t){
        .sponge = SPONGE_INIT(16, 0x1f, 0x80, cGimli),
        .state.u32 = {0}, 
    };
}

void Gimli_XOF_Write(
    gimli_xof_t *restrict x,
    void const *restrict data,
    size_t len)
{
    Sponge_Update(&x->sponge, data, len);
}

void Gimli_XOF_Final(gimli_xof_t *restrict x)
{
    Sponge_Final(&x->sponge);
}

void Gimli_XOF_Read(gimli_xof_t *restrict x, void *restrict data, size_t len)
{
    Sponge_Read(&x->sponge, data, len);
}

IntPtr iGimli_XOF(int q){ return cGimli_XOF(q); }
