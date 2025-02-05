/* DannyNiu/NJF, 2025-01-28. Public Domain. */

#include "ascon-hash.h"
#include "../0-datum/endian.h"

static void Ascon_P12(void const *in, void *out)
{
    return Ascon_Permute(in, out, 12);
}

#define xAscon_P12(q) (                         \
        q==blockBytes ? 40 :                    \
        q==PermuteFunc ? (IntPtr)Ascon_P12 :    \
        0 )

void Ascon_Hash256_Init(ascon_hash256_t *restrict x)
{
    *x = (ascon_hash256_t){
        .sponge = SPONGE_INIT(8, 0x01, 0, xAscon_P12),
        .state[0].u64 = { [0] = htole64(0x0000080100cc0002), },
    };
    Ascon_P12(x->state[0].u8, x->state[0].u8);
}

void Ascon_Hash256_Update(
    ascon_hash256_t *restrict x, void const *restrict data, size_t len)
{
    Sponge_Update(&x->sponge, data, len);
}

// 2021-08-17:
// It's very fortunate that SHA3 hash lengths don't exceed
// the sponge rate parameters (1 block).

void Ascon_Hash256_Final(
    ascon_hash256_t *restrict x, void *restrict out, size_t t)
{
    size_t hlen = 32;

    if( !x->sponge.finalized )
    {
        Sponge_Final(&x->sponge);
        Sponge_Save(&x->sponge);
    }

    Sponge_Restore(&x->sponge);
    Sponge_Read(&x->sponge, out, t < hlen ? t : hlen);

    for(; hlen < t; hlen++)
        ((uint8_t *)out)[hlen] = 0;
}

IntPtr iAscon_Hash256(int q)
{
    return xAscon_Hash256(q);
}
