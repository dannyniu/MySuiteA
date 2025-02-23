/* DannyNiu/NJF, 2024-09-01. Public Domain. */

#include "mldsa.c"
#include "mldsa-paramset.c"
#include "../2-hash/sha.h"
#include "../2-hash/sha3.h"
#include "../2-xof/shake.h"

#include "../test-utils.c.h"

void FixedPRNG(void const *restrict randstr, void *restrict out, size_t len)
{
    scanhex(out, len, randstr);
}

int main(int argc, char *argv[])
{
    MLDSA_Pub_Ctx_Hdr_t *ctx;
    CryptoParam_t *param;

    bufvec_t bufelem = {0};
    bool ph = false;

    size_t len, msglen;
    uint8_t *kdat = NULL, *msg = NULL, *aad = NULL;

    bool verified = false;

    assert( argc == 7 );

    //
    // argv[1]: parameter set.

    if( strcmp(argv[1], "ML-DSA-44") == 0 ) param = MLDSA44.param;
    if( strcmp(argv[1], "ML-DSA-65") == 0 ) param = MLDSA65.param;
    if( strcmp(argv[1], "ML-DSA-87") == 0 ) param = MLDSA87.param;

    //
    // argv[2]: hashAlg.

    if( strcmp(argv[2], "none") == 0 )
        param[2].info = iCryptoObj_Null, ph = false;
    else ph = true;
    if( strcmp(argv[2], "SHA2-224") == 0 ) param[2].info = iSHA224;
    if( strcmp(argv[2], "SHA2-256") == 0 ) param[2].info = iSHA256;
    if( strcmp(argv[2], "SHA2-384") == 0 ) param[2].info = iSHA384;
    if( strcmp(argv[2], "SHA2-512") == 0 ) param[2].info = iSHA512;
    if( strcmp(argv[2], "SHA2-512/224") == 0 ) param[2].info = iSHA512t224;
    if( strcmp(argv[2], "SHA2-512/256") == 0 ) param[2].info = iSHA512t256;
    if( strcmp(argv[2], "SHA3-224") == 0 ) param[2].info = iSHA3_224;
    if( strcmp(argv[2], "SHA3-256") == 0 ) param[2].info = iSHA3_256;
    if( strcmp(argv[2], "SHA3-384") == 0 ) param[2].info = iSHA3_384;
    if( strcmp(argv[2], "SHA3-512") == 0 ) param[2].info = iSHA3_512;
    if( strcmp(argv[2], "SHAKE-128") == 0 ) param[2].info = iSHAKE128;
    if( strcmp(argv[2], "SHAKE-256") == 0 ) param[2].info = iSHAKE256;

    ctx = calloc(1, tMLDSA(param, bytesCtxPub));

    //
    // argv[3]: pk.

    len = strlen(argv[3]) / 2;
    kdat = calloc(1, len);
    scanhex(kdat, len, argv[3]);
    MLDSA_Decode_PublicKey(ctx, kdat, len, param);

    //
    // argv[4]: signature.

    len = strlen(argv[4]) / 2;
    kdat = frealloc(kdat, len);
    scanhex(kdat, len, argv[4]);
    MLDSA_Decode_Signature(ctx, kdat, len);

    //
    // argv[5]: message

    len = strlen(argv[5]) / 2;
    msg = calloc(1, len);
    scanhex(msg, len, argv[5]);
    msglen = len;

    //
    // [re-ordered]: argv[6]: context.

    if( argv[6][0] != '\0' && (aad = memchr("$#", argv[6][0], 2)) )
    {
        //
        // Internal routines' testing.

        if( *aad == '$' )
        {
            // Because decoding of hint contributes to
            // the result of verification, the status
            // must be checked beforehand.
            verified =
                ctx->status > 0 ? true :
                ctx->status < 0 ? false :
                (bool)Dilithium_Verify(ctx, msg);
        }

        else if( *aad == '#' )
        {
            uint8_t mu[64];
            shake256_t hctx;

            SHAKE256_Init(&hctx);
            SHAKE_Write(&hctx, ctx->tr, 64);
            SHAKE_Write(&hctx, msg, msglen);
            SHAKE_Final(&hctx);
            SHAKE_Read(&hctx, mu, 64);

            verified =
                ctx->status > 0 ? true :
                ctx->status < 0 ? false :
                (bool)Dilithium_Verify(ctx, mu);
        }

        aad = NULL;
    }
    else
    {
        //
        // External routines' testing.

        len = strlen(argv[6]) / 2;
        aad = calloc(1, len);
        scanhex(aad, len, argv[6]);

        bufelem.len = len;
        bufelem.buf = aad;
        MLDSA_Verify_Xctrl(ctx, MLDSA_set_ctxstr, &bufelem, 1, 0);

        if( ph )
        {
            void *phctx;
            UpdateFunc_t update;
            phctx = MLDSA_IncVerify_Init(ctx, &update);
            update(phctx, msg, msglen);
            verified = MLDSA_IncVerify_Final(ctx);
        }
        else verified = MLDSA_Verify(ctx, msg, msglen);

        free(aad);
    }

    free(msg);
    free(kdat);
    free(ctx);

    return verified ? 0 : 1;
}
