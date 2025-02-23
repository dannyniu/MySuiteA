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
    MLDSA_Priv_Ctx_Hdr_t *ctx;
    CryptoParam_t *param;

    bufvec_t bufelem = {0};
    GenFunc_t prng_gen;
    void *prng;
    bool ph = false;

    size_t len, msglen, t;
    uint8_t *kdat = NULL, *msg = NULL, *aad = NULL;

    assert( argc == 7 || // hedged.
            argc == 6 ); // deterministic.

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

    ctx = calloc(1, tMLDSA(param, bytesCtxPriv));

    //
    // argv[3]: sk.

    len = strlen(argv[3]) / 2;
    kdat = calloc(1, len);
    scanhex(kdat, len, argv[3]);
    MLDSA_Decode_PrivateKey(ctx, kdat, len, param);

    //
    // argv[4]: msg.

    len = strlen(argv[4]) / 2;
    msg = calloc(1, len);
    scanhex(msg, len, argv[4]);
    msglen = len;

    //
    // [re-ordered]: optional, argv[6]: rnd.

    if( argv[6] )
    {
        prng_gen = (GenFunc_t)FixedPRNG;
        prng = argv[6];
    }
    else
    {
        prng_gen = NULL;
        prng = NULL;
    }

    //
    // [re-ordered]: argv[5]: context.

    if( argv[5][0] != '\0' && (aad = memchr("$#", argv[5][0], 2)) )
    {
        //
        // Internal routines' testing.

        if( *aad == '$' )
            Dilithium_Sign(ctx, msg, prng_gen, prng);

        else if( *aad == '#' )
        {
            uint8_t mu[64];
            shake256_t hctx;

            SHAKE256_Init(&hctx);
            SHAKE_Write(&hctx, ctx->tr, 64);
            SHAKE_Write(&hctx, msg, msglen);
            SHAKE_Final(&hctx);
            SHAKE_Read(&hctx, mu, 64);
            Dilithium_Sign(ctx, mu, prng_gen, prng);
        }

        aad = NULL;
    }
    else
    {
        //
        // External routines' testing.

        len = strlen(argv[5]) / 2;
        aad = calloc(1, len);
        scanhex(aad, len, argv[5]);

        bufelem.len = len;
        bufelem.buf = aad;
        MLDSA_Sign_Xctrl(ctx, MLDSA_set_ctxstr, &bufelem, 1, 0);

        if( ph )
        {
            void *phctx;
            UpdateFunc_t update;
            phctx = MLDSA_IncSign_Init(ctx, &update);
            update(phctx, msg, msglen);
            MLDSA_IncSign_Final(ctx, prng_gen, prng);
        }
        else MLDSA_Sign(ctx, msg, msglen, prng_gen, prng);

        free(aad);
    }

    //
    // output signature.

    MLDSA_Encode_Signature(ctx, NULL, &len);
    kdat = frealloc(kdat, len);
    MLDSA_Encode_Signature(ctx, kdat, &len);
    for(t=0; t<len; t++)
        printf("%02X", kdat[t]);
    printf("\n");//*/

    free(msg);
    free(kdat);
    free(ctx);

    return EXIT_SUCCESS;
}
