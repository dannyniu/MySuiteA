/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#include "../1-symm/gimli.h"
#include "gimli-hash.h"

void Gimli_Hash_Init(gimli_hash_t *restrict x)
{
    *x = (gimli_hash_t){
        .sponge = SPONGE_INIT(16, 0x1f, _iGimli),
        .state.u32 = {}, 
    };
}

void Gimli_Hash_Write(gimli_hash_t *restrict x, const void *restrict data, size_t len)
{
    Sponge_Update(&x->sponge, data, len);
}

void Gimli_Hash_Final(gimli_hash_t *restrict x)
{
    Sponge_Final(&x->sponge);
}

void Gimli_Hash_Read(gimli_hash_t *restrict x, void *restrict data, size_t len)
{
    Sponge_Read(&x->sponge, data, len);
}

intptr_t iGimli_Hash(int q){ return _iGimli_Hash(q); }
