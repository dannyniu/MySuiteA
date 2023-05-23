/* DannyNiu/NJF, 2023-05-18. Public Domain. */

#include "ecc-dss-sign-hedged.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

#ifdef DSS_SIGN_HEDGED_SM2
#include "../3-sm2/sm2sig.h"
#define IsSM2 (signer == SM2SIG_Sign)
#else
#define IsSM2 false
#endif /* DSS_SIGN_HEDGED_SM2 */

void *ECC_Hedged_Sign(
    ECC_Hash_Ctx_Hdr_t *restrict x,
    hmac_drbg_t *restrict prng,
    PKSignFunc_t signer,
    void const *restrict msg, size_t msglen,
    void const *restrict nonce, size_t nlen)
{
    uint8_t str[512] = {0};
    unsigned i = 0, t = 0;

    void *restrict hashctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hx = &x->hfuncs;

    vlong_t *vl;

    assert( ((x->curve->plen * 2 + 255) & ~255) + x->hlen < sizeof(str) );

    // Z.

    if( nlen > x->curve->plen )
    {
        hx->initfunc(hashctx);
        hx->updatefunc(hashctx, nonce, nlen);

        if( hx->xfinalfunc )
            hx->xfinalfunc(hashctx);

        hx->hfinalfunc(hashctx, str+t, x->hlen);
        t += x->hlen;
    }
    else
    {
        for(i=0; i<nlen; i++)
        {
            str[t++] = ((uint8_t const *)nonce)[i];
        }
    }

    // int2octets(x).

    vl = DeltaTo(x, offset_d);
    vlong_I2OSP(vl, str+t, x->curve->plen);
    t += x->curve->plen;

    // 000...

    if( prng->prf_blklen > 1 )
    {
        t += prng->prf_outlen + 1;
        t += prng->prf_blklen - 1;
        t -= t % prng->prf_blklen;
        t -= prng->prf_outlen + 1;
    }
    else t += 1;

    // bits2octets(h1).

    hx->initfunc(hashctx);

    if( IsSM2 )
    {
        x->status = 3;
        hx->updatefunc(hashctx, x->uinfo, x->hlen);
    }
    else x->status = 2;

    hx->updatefunc(hashctx, msg, msglen);

    if( hx->xfinalfunc )
        hx->xfinalfunc(hashctx);

    hx->hfinalfunc(hashctx, str+t, x->hlen);
    t += x->hlen;

    // Seeding & Signing.

    HMAC_DRBG_Seed(prng, str, t);
    return signer(x, msg, msglen, (GenFunc_t)HMAC_DRBG_Generate, prng);
}
