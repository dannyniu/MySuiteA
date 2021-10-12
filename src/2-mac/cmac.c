/* DannyNiu/NJF, 2018-02-18. Public Domain. */

#include "cmac.h"
#include "../0-exec/struct-delta.c.h"

#define R_128 0x87

void *CMAC_SetKey(cmac_t *restrict cmac, const void *restrict key, size_t keylen)
{
    void *aux = DeltaTo(cmac, offset);
    size_t i;
    uint8_t b; // same size as R_blksize - 1 octet for now.

    if( keylen != (unsigned)cmac->keylen_valid ) return NULL;
    // Assume block size of the blockcipher is the supported 128-bit.

    if( !cmac->kschd ) return NULL; // static assertion from CMAC_INIT macro.
    cmac->kschd(key, aux);

    // also done by CMAC_INIT. [2021-07-22]: evaluate code redundance later.
    for(i=0; i<CMAC_BLKSIZE; i++) cmac->T[i] = cmac->K1[i] = cmac->K2[i] = 0;

    cmac->enc(cmac->K1, cmac->K1, aux);
    b = cmac->K1[0] >> 7;
    for(i=1; i<CMAC_BLKSIZE; i++)
        cmac->K1[i - 1] = cmac->K1[i - 1] << 1 | cmac->K1[i] >> 7;
    cmac->K1[i - 1] = (cmac->K1[i - 1] << 1) ^ (R_128 & (0 - b));

    for(i=0; i<CMAC_BLKSIZE; i++) cmac->K2[i] = cmac->K1[i];
    b = cmac->K2[0] >> 7;
    for(i=1; i<CMAC_BLKSIZE; i++)
        cmac->K2[i - 1] = cmac->K2[i - 1] << 1 | cmac->K2[i] >> 7;
    cmac->K2[i - 1] = (cmac->K2[i - 1] << 1) ^ (R_128 & (0 - b));

    // also done by CMAC_INIT, see note above tagged [2021-07-22].
    cmac->filled = 0;
    cmac->finalized = false;
    
    return cmac;
}

void CMAC_Update(cmac_t *restrict cmac, const void *restrict data, size_t len)
{
    void *aux = DeltaTo(cmac, offset);
    uint8_t const *buffer = data;

    if( cmac->filled >= CMAC_BLKSIZE && len )
    {
        cmac->enc(cmac->T, cmac->T, aux);
        cmac->filled = 0;
    }

    while( len )
    {
        cmac->T[cmac->filled++] ^= *(buffer++);
        len--;

        if( cmac->filled >= CMAC_BLKSIZE && len )
        {
            cmac->enc(cmac->T, cmac->T, aux);
            cmac->filled = 0;
        }
    }
}

void CMAC_Final(cmac_t *restrict cmac, void *restrict out, size_t t)
{
    void *aux = DeltaTo(cmac, offset);
    size_t i;

    if( cmac->finalized ) goto finalized;

    if( cmac->filled >= CMAC_BLKSIZE )
    {
        for(i=0; i<CMAC_BLKSIZE; i++)
            cmac->T[i] ^= cmac->K1[i];
        cmac->enc(cmac->T, cmac->T, aux);
    }
    else
    {
        cmac->T[cmac->filled++] ^= 0x80;
        for(i=0; i<CMAC_BLKSIZE; i++)
            cmac->T[i] ^= cmac->K2[i];
        cmac->filled = 0;
        cmac->enc(cmac->T, cmac->T, aux);
    }

    cmac->finalized = true;

finalized:
    for(i=0; i<t && i<CMAC_BLKSIZE; i++)
        ((uint8_t *)out)[i] = cmac->T[i];
    
    for(; i<t; i++)
        ((uint8_t *)out)[i] = 0;
}

#define cT(q) (P->param ? P->template(P->param, q) : P->info(q))

IntPtr tCMAC(const CryptoParam_t *P, int q) { return xCMAC(T,q); }

void *CMAC_T_Init(
    const CryptoParam_t *restrict P,
    cmac_t *restrict x,
    void const *restrict key,
    size_t keylen)
{
    *x = CMAC_INIT(cT);
    x = CMAC_SetKey(x, key, keylen);
    return x;
}
