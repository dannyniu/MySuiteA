/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#include "../1-symm/gimli.h"
#include "gimli-xof.h"

void Gimli_XOF_Init(gimli_xof_t *restrict x)
{
    *x = (gimli_xof_t){
        .sponge = SPONGE_INIT(16, 0x1f, 0x80, xGimli),
        .state = {0},
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
    // See 2023-05-17 note in "shake.c".

    if( !x->sponge.finalized )
    {
        Sponge_Final(&x->sponge);
        Sponge_Save(&x->sponge);
    }
    else Sponge_Restore(&x->sponge);
}

void Gimli_XOF_Read(gimli_xof_t *restrict x, void *restrict data, size_t len)
{
    Sponge_Read(&x->sponge, data, len);
}

IntPtr iGimli_XOF(int q){ return xGimli_XOF(q); }
