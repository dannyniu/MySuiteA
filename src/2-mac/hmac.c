/* DannyNiu/NJF, 2018-02-18. Public Domain. */

#include "hmac.h"

#define ipad 0x36
#define opad 0x5c

void HMAC_SetKey(hmac_t *restrict hmac, const void *restrict key, size_t keylen)
{
    void *aux = (uint8_t *)hmac + hmac->offset;
    size_t i;

    for(i=0; i<sizeof(hmac->K0); i++) hmac->K0[i] = 0;
    for(i=0; i<sizeof(hmac->tag); i++) hmac->tag[i] = 0;
        
    if( keylen <= hmac->B )
    {
        for(i=0; i<(keylen); i++)
            hmac->K0[i] = ((const uint8_t *)key)[i];
    }
    else
    {
        hmac->hInit(aux);
        hmac->hUpdate(aux, key, keylen);
        hmac->hFinal(aux, hmac->K0, hmac->L);
    }
        
    hmac->hInit(aux);
    for(i=0; i<hmac->B; i++) hmac->K0[i] ^= ipad;
    hmac->hUpdate(aux, hmac->K0, hmac->B);
    for(i=0; i<hmac->B; i++) hmac->K0[i] ^= ipad;
}

void HMAC_Update(hmac_t *restrict hmac, const void *restrict data, size_t len)
{
    hmac->hUpdate((uint8_t *)hmac + hmac->offset, data, len);
}

void HMAC_Final(hmac_t *restrict hmac, void *restrict out, size_t t)
{
    void *aux = (uint8_t *)hmac + hmac->offset;
    size_t i;

    if( hmac->finalized ) goto finalized;

    hmac->hFinal(aux, hmac->tag, hmac->L);

    hmac->hInit(aux);
    for(i=0; i<hmac->B; i++) hmac->K0[i] ^= opad;
    (hmac)->hUpdate(aux, hmac->K0, hmac->B);
    for(i=0; i<hmac->B; i++) hmac->K0[i] = 0; // clears key.

    hmac->hUpdate(aux, hmac->tag, hmac->L);
    hmac->hFinal(aux, NULL, 0);
    hmac->finalized = 1;

finalized:
    // After aligning the interface of hash and mac (by adding outlen param)
    // the code is slightly simpler.
    hmac->hFinal(aux, out, t);
}

#define cT(q) (P->param ? P->template(P->param, q) : P->info(q))

IntPtr tHMAC(const CryptoParam_t *P, int q)
{
    return cHMAC(T,q);
}

void *HMAC_T_Init(
    const CryptoParam_t *restrict P,
    hmac_t *restrict x,
    void const *restrict key,
    size_t keylen)
{
    *x = HMAC_INIT(cT);
    HMAC_SetKey(x, key, keylen);
    return x;
}
