/* DannyNiu/NJF, 2021-08-31. Public Domain. */

#include "pkcs1-padding.h"
#include "../0-datum/endian.h"

void mgf1_pkcs1(
    pkcs1_padding_oracles_t *restrict x,
    void const *restrict in, size_t inlen,
    void *restrict out, size_t outlen, int xor)
{
    // 2021-09-11:
    // This function is being tested through RSA-OAEP cipher,
    // currently passing self-feeding tests, but not ones using
    // publicly available test vectors.
    
    size_t t, i;
    uint8_t *dst = out;
    uint8_t buf[64]; // assume hash functions are 512-bit maximum.
    uint32_t c = htobe32(0);
    hash_funcs_set_t *hx = &x->base.hfuncs_mgf;

    while( outlen )
    {
        t = x->base.hlen_mgf < outlen ? x->base.hlen_mgf : outlen;

        hx->initfunc(x->hashctx);
        hx->updatefunc(x->hashctx, in, inlen);
        hx->updatefunc(x->hashctx, &c, sizeof(c));
        hx->hfinalfunc(x->hashctx, buf, t);

        if( xor )
            for(i=0; i<t; i++) dst[i] ^= buf[i];
        else for(i=0; i<t; i++) dst[i] = buf[i];
        
        dst += t;
        outlen -= t;
        c = htobe32(be32toh(c) + 1);
    }
}

void mgf_xof(
    pkcs1_padding_oracles_t *restrict x,
    void const *restrict in, size_t inlen,
    void *restrict out, size_t outlen, int xor)
{
    // 2021-09-03: This function had not been tested yet //
    size_t t, i;
    uint8_t *dst = out;
    uint8_t buf[16];
    hash_funcs_set_t *hx = &x->base.hfuncs_mgf;

    hx->initfunc(x->hashctx);
    hx->updatefunc(x->hashctx, in, inlen);
    hx->xfinalfunc(x->hashctx);

    while( outlen )
    {
        t = sizeof(buf) < outlen ? sizeof(buf) : outlen;
        hx->hfinalfunc(x->hashctx, buf, t);
        
        if( xor )
            for(i=0; i<t; i++) dst[i] ^= buf[i];
        else for(i=0; i<t; i++) dst[i] = buf[i];
        
        dst += t;
        outlen -= t;
    }
}

void mgf_auto(
    pkcs1_padding_oracles_t *restrict x,
    void const *restrict in, size_t inlen,
    void *restrict out, size_t outlen, int xor)
{
    // 2021-09-03: This function had not been tested yet //
    if( !x->base.hfuncs_mgf.xfinalfunc )
        return mgf1_pkcs1(x, in, inlen, out, outlen, xor);
    else return mgf_xof(x, in, inlen, out, outlen, xor);
}
