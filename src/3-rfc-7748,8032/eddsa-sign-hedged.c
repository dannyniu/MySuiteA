/* DannyNiu/NJF, 2023-05-19. Public Domain. */

#include "eddsa-sign-hedged.h"
#include "../2-hash/sha.h"
#include "../2-xof/shake.h"

void *EdDSA_Hedged_Sign(
    EdDSA_Ctx_Hdr_t *restrict x,
    void *restrict hash,
    PKSignFunc_t signer,
    void const *restrict msg, size_t msglen,
    void const *restrict nonce, size_t nlen)
{
    void *hctx;
    hash_funcs_set_t *hfnx = &x->hfuncs;
    unsigned plen = (x->curve->pbits + 8) / 8;
    unsigned i, t, b;

    uint8_t buf[256] = {0};

    assert( signer == (PKSignFunc_t)EdDSA_Sign );

    assert( hfnx->initfunc == SHA512_Init ||
            hfnx->initfunc == SHAKE256_Init );

    // Determine Block Size.

    if( hfnx->initfunc == (InitFunc_t)SHA512_Init ) b = 128;
    if( hfnx->initfunc == (InitFunc_t)SHAKE256_Init ) b = 136;

    // DOM String.

    hctx = DeltaTo(x, offset_hashctx_init);

    for(i=0; i<x->hashctx_size; i++)
        ((uint8_t *)hash)[i] = ((uint8_t *)hctx)[i];

    t = x->domlen;

    // 'Z' and 'prefix'.

    hfnx->updatefunc(hash, nonce, nlen);
    hfnx->updatefunc(hash, x->prefix, plen);

    // 000...

    t += nlen + plen;
    t %= b;
    t = b - t;
    hfnx->updatefunc(hash, buf, t);

    // PH(M).

    hctx = DeltaTo(x, offset_hashctx);

    if( x->flags & EdDSA_Flags_PH )
    {
        x->status = 2;
        hfnx->initfunc(hctx);
        hfnx->updatefunc(hctx, msg, msglen);

        if( hfnx->xfinalfunc )
            hfnx->xfinalfunc(hctx);

        // consult [2023-05-19:outlen-64] in "eddsa.c".
        hfnx->hfinalfunc(hctx, buf, 64);
        hfnx->updatefunc(hash, buf, 64);
    }
    else hfnx->updatefunc(hash, msg, msglen);

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(hash);

    return signer(x, msg, msglen, hfnx->hfinalfunc, hash);
}
