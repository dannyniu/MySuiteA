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

#define SEED_STRLEN 640

void *ECC_Hedged_Sign(
    ECC_Hash_Ctx_Hdr_t *restrict x,
    hmac_drbg_t *restrict hrng,
    PKSignFunc_t signer,
    void const *restrict msg, size_t msglen,
    void const *restrict nonce, size_t nlen)
{
    uint8_t d[128];
    uint8_t h[64];

    bufvec_t bv[5] = {
        [0].len = nlen,
        [0].dat = nonce,
        [1].len = 1,
        [1].dat = NULL,
        [2].len = x->curve->plen,
        [2].dat = d,
        [3].len = 1,
        [3].dat = NULL,
        [4].len = x->hlen,
        [4].dat = h,
    };

    void *restrict hctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hfnx = &x->hfuncs;

    vlong_I2OSP(DeltaTo(x, offset_d), d, x->curve->plen);

    hfnx->initfunc(hctx);
    hfnx->updatefunc(hctx, msg, msglen);

    if( IsSM2 )
    {
        x->status = 3;
        hfnx->updatefunc(hctx, x->uinfo, x->hlen);
    }
    else x->status = 2;

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(hctx);

    hfnx->hfinalfunc(hctx, h, x->hlen);

    // Seeding & Signing.

    HMAC_DRBG_VecSeed(hrng, bv, 5);
    return signer(x, msg, msglen, (GenFunc_t)HMAC_DRBG_Generate, hrng);
}

void *ECC_Hedged_IncSign_Final(
    ECC_Hash_Ctx_Hdr_t *restrict x,
    hmac_drbg_t *restrict hrng,
    PKIncSignFinalFunc_t signer,
    void const *restrict nonce, size_t nlen)
{
    uint8_t d[128];
    uint8_t h[64];

    bufvec_t bv[5] = {
        [0].len = nlen,
        [0].dat = nonce,
        [1].len = 1,
        [1].dat = NULL,
        [2].len = x->curve->plen,
        [2].dat = d,
        [3].len = 1,
        [3].dat = NULL,
        [4].len = x->hlen,
        [4].dat = h,
    };

    void *restrict hctx = DeltaTo(x, offset_hashctx);
    hash_funcs_set_t *hfnx = &x->hfuncs;

    vlong_I2OSP(DeltaTo(x, offset_d), d, x->curve->plen);

    if( IsSM2 )
    {
        x->status = 3;
    }
    else x->status = 2;

    if( hfnx->xfinalfunc )
        hfnx->xfinalfunc(hctx);

    hfnx->hfinalfunc(hctx, h, x->hlen);

    // Seeding & Signing.

    HMAC_DRBG_VecSeed(hrng, bv, 5);
    return signer(x, (GenFunc_t)HMAC_DRBG_Generate, hrng);
}
