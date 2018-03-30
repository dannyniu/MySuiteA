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
            hmac->K0[i] = ((uint8_t *)key)[i];
    }
    else
    {
        hmac->hInit(aux);
        hmac->hUpdate(aux, key, keylen);
        hmac->hFinal(aux, hmac->K0);
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
    if( hmac->finalized ) goto finalized;

    size_t i;
    void *aux = (uint8_t *)hmac + hmac->offset;

    hmac->hFinal(aux, hmac->tag);

    hmac->hInit(aux);
    for(i=0; i<hmac->B; i++) hmac->K0[i] ^= opad;
    (hmac)->hUpdate(aux, hmac->K0, hmac->B);
    for(i=0; i<hmac->B; i++) hmac->K0[i] = 0; // clears key.

    hmac->hUpdate(aux, hmac->tag, hmac->L);
    hmac->hFinal(aux, hmac->tag);
    hmac->finalized = 1;

finalized:
    if( out ) {
        // zero-extends if t>L. 
        for(i=0; i<t; i++)
            ((uint8_t *)out)[i] = i<hmac->L ? hmac->tag[i] : 0;
    }
}
