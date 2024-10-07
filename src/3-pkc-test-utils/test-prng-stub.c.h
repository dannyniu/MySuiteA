/* DannyNiu/NJF, 2022-02-25. Public Domain. */

#include "../2-xof/gimli-xof.h"
static gimli_xof_t gx, mx;

void *prng = &gx;

void PKC_PRNG_Init(void const *additional_input, size_t alen)
{
    Gimli_XOF_Init(&gx);
    Gimli_XOF_Write(&gx, "Hello World!", 12);
    if( additional_input )
        Gimli_XOF_Write(&gx, additional_input, alen);
    Gimli_XOF_Final(&gx);
}

void PKC_PRNG_Gen(void *restrict x, void *restrict data, size_t len)
{
    Gimli_XOF_Read(x == prng ? x : prng, data, len);
}
