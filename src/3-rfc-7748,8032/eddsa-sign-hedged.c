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
    void *hx;
    unsigned plen = (x->curve->pbits + 8) / 8;
    unsigned i, t, b;

    uint8_t buf[256] = {0};

    assert( signer == (PKSignFunc_t)EdDSA_Sign );

    assert( x->hfuncs.initfunc == SHA512_Init ||
            x->hfuncs.initfunc == SHAKE256_Init );

    // Determine Block Size.

    if( x->hfuncs.initfunc == (InitFunc_t)SHA512_Init ) b = 128;
    if( x->hfuncs.initfunc == (InitFunc_t)SHAKE256_Init ) b = 136;

    // DOM String.

    hx = DeltaTo(x, offset_hashctx_init);

    for(i=0; i<x->hashctx_size; i++)
        ((uint8_t *)hash)[i] = ((uint8_t *)hx)[i];

    t = x->domlen;

    // 'Z' and 'prefix'.

    x->hfuncs.updatefunc(hash, nonce, nlen);
    x->hfuncs.updatefunc(hash, x->prefix, plen);

    // 000...

    t += nlen + plen;
    t %= b;
    t = b - t;
    x->hfuncs.updatefunc(hash, buf, t);

    // PH(M).

    hx = DeltaTo(x, offset_hashctx);

    if( x->flags & EdDSA_Flags_PH )
    {
        x->status = 2;
        x->hfuncs.initfunc(hx);
        x->hfuncs.updatefunc(hx, msg, msglen);

        if( x->hfuncs.xfinalfunc )
            x->hfuncs.xfinalfunc(hx);

        // consult [2023-05-19:outlen-64] in "eddsa.c".
        x->hfuncs.hfinalfunc(hx, buf, 64);
        x->hfuncs.updatefunc(hash, buf, 64);
    }
    else x->hfuncs.updatefunc(hash, msg, msglen);

    if( x->hfuncs.xfinalfunc )
        x->hfuncs.xfinalfunc(hash);

    return signer(x, msg, msglen, x->hfuncs.hfinalfunc, hash);
}
