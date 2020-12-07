/* DannyNiu/NJF, 2020-11-28. Public Domain. */

#include "hmac-drbg.h"

static void HMAC_DRBG_Update(
    hmac_drbg_t *restrict x,
    void const *restrict str,
    size_t len)
{
    size_t outlen = x->prf_outlen;
    void *K = ((uint8_t *)x + x->offset_k);
    void *V = ((uint8_t *)x + x->offset_v);
    void *H = ((uint8_t *)x + x->prf_ctx_offset);
    uint8_t c;

    c = 0;
    
    x->prf_init(H, K, outlen);
    x->prf_update(H, V, outlen);
    x->prf_update(H, &c, 1);
    x->prf_update(H, str, len);
    x->prf_final(H, K, outlen);
    
    x->prf_init(H, K, outlen);
    x->prf_update(H, V, outlen);
    x->prf_final(H, V, outlen);

    if( !len ) return;
    
    c = 1;
    
    x->prf_init(H, K, outlen);
    x->prf_update(H, V, outlen);
    x->prf_update(H, &c, 1);
    x->prf_update(H, str, len);
    x->prf_final(H, K, outlen);

    x->prf_init(H, K, outlen);
    x->prf_update(H, V, outlen);
    x->prf_final(H, V, outlen);
}

void HMAC_DRBG_Seed(
    hmac_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len)
{
    size_t outlen = x->prf_outlen;
    uint8_t *K = (uint8_t *)x + x->offset_k;
    uint8_t *V = (uint8_t *)x + x->offset_v;

    while( outlen-- ) K[outlen] = 0, V[outlen] = 1;
    HMAC_DRBG_Update(x, seedstr, len);
}

void HMAC_DRBG_Reseed(
    hmac_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len)
{
    HMAC_DRBG_Update(x, seedstr, len);
}

void HMAC_DRBG_Generate(
    hmac_drbg_t *restrict x,
    void *restrict out,
    size_t len)
{
    size_t outlen = x->prf_outlen;
    void *K = ((uint8_t *)x + x->offset_k);
    void *V = ((uint8_t *)x + x->offset_v);
    void *H = ((uint8_t *)x + x->prf_ctx_offset);

    uint8_t *buf = out;
    size_t tmplen = 0;
    size_t t;

    while( tmplen < len )
    {
        x->prf_init(H, K, outlen);
        x->prf_update(H, V, outlen);
        x->prf_final(H, V, outlen);
        
        for(t = 0; t < outlen && tmplen < len; t++, tmplen++)
            buf[tmplen] = ((uint8_t *)V)[t];
    }
}
