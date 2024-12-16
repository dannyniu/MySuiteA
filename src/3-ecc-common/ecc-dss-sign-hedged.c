/* DannyNiu/NJF, 2023-05-18. Public Domain. */

#include "ecc-dss-sign-hedged.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

#ifdef DSS_SIGN_HEDGED_SM2
#include "../3-sm2/sm2sig.h"
#define IsSM2 (signer == SM2SIG_Sign || signer == SM2SIG_IncSign_Final)
#else
#define IsSM2 false
#endif /* DSS_SIGN_HEDGED_SM2 */

// 168 is the rate of SHAKE-128,
// 136 is the rate of SHAKE-256,
// 128 is the block size of SHA-512,
// 64 is the block size of SHA-256.
// 640 > 168 * 2 + 64.
#define SEED_STRLEN 640

bool ECC_Hedged_Sign_Prelude(
    ECC_Hash_Ctx_Hdr_t *restrict x, uint8_t *str,
    hmac_drbg_t *restrict hrng, unsigned *t_ptr,
    void const *restrict nonce, size_t nlen)
{
    unsigned i = 0, t = *t_ptr;

    void *restrict hctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hfnx = &x->hfuncs;

    vlong_t *vl;

    assert( ((x->curve->plen + 255) & ~255) * 2 + x->hlen < SEED_STRLEN );

    // Z.

    if( nlen > x->curve->plen )
    {
        hfnx->initfunc(hctx);
        hfnx->updatefunc(hctx, nonce, nlen);

        if( hfnx->xfinalfunc )
            hfnx->xfinalfunc(hctx);

        hfnx->hfinalfunc(hctx, str+t, x->hlen);
        t += x->hlen;
    }
    else
    {
        for(i=0; i<nlen; i++)
        {
            str[t++] = ((uint8_t const *)nonce)[i];
        }
    }

    // 000...

    if( hrng->prf_blklen > 1 )
    {
        t += hrng->prf_outlen + 1; // V and 1 pad byte.
        t += hrng->prf_blklen - 1; // 00h x (blklen - 1).
        t -= t % hrng->prf_blklen; // mod arith.
        t -= hrng->prf_outlen + 1; // V and 1 pad byte.
    }
    else t += 1;

    // int2octets(x).

    vl = DeltaTo(x, offset_d);
    vlong_I2OSP(vl, str+t, x->curve->plen);
    t += x->curve->plen;

    // 000...

    if( hrng->prf_blklen > 1 )
    {
        t += hrng->prf_outlen + 1; // V and 1 pad byte.
        t += hrng->prf_blklen - 1; // 00h x (blklen - 1).
        t -= t % hrng->prf_blklen; // mod arith.
        t -= hrng->prf_outlen + 1; // V and 1 pad byte.
    }
    else t += 1;

    // bits2octets(h1).

    hfnx->initfunc(hctx);

    // Leaving Prelude.

    *t_ptr = t;
    return true;
}

void *ECC_Hedged_Sign(
    ECC_Hash_Ctx_Hdr_t *restrict x,
    hmac_drbg_t *restrict hrng,
    PKSignFunc_t signer,
    void const *restrict msg, size_t msglen,
    void const *restrict nonce, size_t nlen)
{
    uint8_t str[SEED_STRLEN] = {0};
    unsigned t = 0;

    void *restrict hctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hfnx = &x->hfuncs;

    if( !ECC_Hedged_Sign_Prelude(x, str, hrng, &t, nonce, nlen) )
        return NULL;

    if( IsSM2 )
    {
        x->status = 3;
        hfnx->updatefunc(hctx, x->uinfo, x->hlen);
    }
    else x->status = 2;

    hfnx->updatefunc(hctx, msg, msglen);

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(hctx);

    hfnx->hfinalfunc(hctx, str+t, x->hlen);
    t += x->hlen;

    // Seeding & Signing.

    HMAC_DRBG_Seed(hrng, str, t);
    return signer(x, msg, msglen, (GenFunc_t)HMAC_DRBG_Generate, hrng);
}

void *ECC_Hedged_IncSign_Final(
    ECC_Hash_Ctx_Hdr_t *restrict x,
    hmac_drbg_t *restrict hrng,
    PKIncSignFinalFunc_t signer,
    void const *restrict nonce, size_t nlen)
{
    // 168 is the rate of SHAKE-128,
    // 136 is the rate of SHAKE-256,
    // 128 is the block size of SHA-512,
    // 64 is the block size of SHA-256.
    // 640 > 168 * 2 + 64.
    uint8_t str[SEED_STRLEN] = {0};
    unsigned t = 0;

    void *restrict hctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hfnx = &x->hfuncs;

    if( !ECC_Hedged_Sign_Prelude(x, str, hrng, &t, nonce, nlen) )
        return NULL;

    if( IsSM2 )
    {
        x->status = 3;
    }
    else x->status = 2;

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(hctx);

    hfnx->hfinalfunc(hctx, str+t, x->hlen);
    t += x->hlen;

    // Seeding & Signing.

    HMAC_DRBG_Seed(hrng, str, t);
    return signer(x, (GenFunc_t)HMAC_DRBG_Generate, hrng);
}
