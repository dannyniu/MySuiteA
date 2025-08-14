/* DannyNiu/NJF, 2025-01-27. Public Domain. */

#include "ascon-xof.h"
#include "../0-datum/endian.h"

static void Ascon_P12(void const *in, void *out)
{
    return Ascon_Permute(in, out, 12);
}

#define xAscon_P12(q) (                         \
        q==blockBytes ? 40 :                    \
        q==PermuteFunc ? (IntPtr)Ascon_P12 :    \
        0 )

void Ascon_XOF128_Init(ascon_xof128_t *restrict x)
{
    *x = (ascon_xof128_t){
        .sponge = SPONGE_INIT(8, 0x01, 0, xAscon_P12),
        .state[0].u64 = { [0] = htole64(0x0000080000cc0003), },
    };
    Ascon_P12(x->state[0].u8, x->state[0].u8);
}

void Ascon_CXOF128_KInit(
    ascon_cxof128_t *restrict x, const void *restrict Z, size_t len)
{
    uint64_t Z0;

    *x = (ascon_cxof128_t){
        .sponge = SPONGE_INIT(8, 0x01, 0, xAscon_P12),
        .state[0].u64 = { [0] = htole64(0x0000080000cc0004), },
    };
    Ascon_P12(x->state[0].u8, x->state[0].u8);

    Z0 = len * 8;
    Z0 = htole64(Z0);
    Sponge_Update(&x->sponge, &Z0, 8);
    Sponge_Update(&x->sponge, Z, len);
    Sponge_Final(&x->sponge);
    x->sponge.finalized = false;
}

void Ascon_XOF128_Write(
    ascon_xof128_t *restrict x, const void *restrict data, size_t len)
{
    Sponge_Update(&x->sponge, data, len);
}

void Ascon_XOF128_Final(ascon_xof128_t *restrict x)
{
    if( !x->sponge.finalized )
    {
        Sponge_Final(&x->sponge);
        Sponge_Save(&x->sponge);
    }
    else Sponge_Restore(&x->sponge);
}

void Ascon_XOF128_Read(
    ascon_xof128_t *restrict x, void *restrict data, size_t len)
{
    Sponge_Read(&x->sponge, data, len);
}

IntPtr iAscon_XOF128(int q)
{
    return xAscon_XOF128(q);
}
