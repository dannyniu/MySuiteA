/* DannyNiu/NJF, 2024-09-01. Public Domain. */

#include "slhdsa-paramset.h"

#include "../test-utils.c.h"

void FixedPRNG(void const *restrict randstr, void *restrict out, size_t len)
{
    scanhex(out, len, randstr);
}

int main(int argc, char *argv[])
{
    SLHDSA_Ctx_Hdr_t *ctx;
    CryptoParam_t *param;

    IntPtr lret, t;
    uint8_t *kdat = NULL;

    //
    // argv[1]: parameter set.

    if( strcmp(argv[1], "SLH-DSA-SHA2-128s") == 0 ) param = SLHDSA_SHA2_128s.param;
    if( strcmp(argv[1], "SLH-DSA-SHA2-192s") == 0 ) param = SLHDSA_SHA2_192s.param;
    if( strcmp(argv[1], "SLH-DSA-SHA2-256s") == 0 ) param = SLHDSA_SHA2_256s.param;
    if( strcmp(argv[1], "SLH-DSA-SHA2-128f") == 0 ) param = SLHDSA_SHA2_128f.param;
    if( strcmp(argv[1], "SLH-DSA-SHA2-192f") == 0 ) param = SLHDSA_SHA2_192f.param;
    if( strcmp(argv[1], "SLH-DSA-SHA2-256f") == 0 ) param = SLHDSA_SHA2_256f.param;
    if( strcmp(argv[1], "SLH-DSA-SHAKE-128s") == 0 ) param = SLHDSA_SHAKE_128s.param;
    if( strcmp(argv[1], "SLH-DSA-SHAKE-192s") == 0 ) param = SLHDSA_SHAKE_192s.param;
    if( strcmp(argv[1], "SLH-DSA-SHAKE-256s") == 0 ) param = SLHDSA_SHAKE_256s.param;
    if( strcmp(argv[1], "SLH-DSA-SHAKE-128f") == 0 ) param = SLHDSA_SHAKE_128f.param;
    if( strcmp(argv[1], "SLH-DSA-SHAKE-192f") == 0 ) param = SLHDSA_SHAKE_192f.param;
    if( strcmp(argv[1], "SLH-DSA-SHAKE-256f") == 0 ) param = SLHDSA_SHAKE_256f.param;

    ctx = calloc(1, tSLHDSA(param, bytesCtxPriv));

    //
    // argv[2]: seed.

    SLHDSA_Keygen(ctx, param, (GenFunc_t)FixedPRNG, argv[2]);

    //
    // print private key.

    lret = SLHDSA_Encode_PrivateKey(ctx, NULL, 0, NULL);
    kdat = frealloc(kdat, lret);
    SLHDSA_Encode_PrivateKey(ctx, kdat, lret, NULL);

    for(t=0; t<lret; t++)
        printf("%02X", kdat[t]);
    printf(":");

    //
    // print public key.

    lret = SLHDSA_Export_PublicKey(ctx, NULL, 0, NULL);
    kdat = frealloc(kdat, lret);
    SLHDSA_Export_PublicKey(ctx, kdat, lret, NULL);

    for(t=0; t<lret; t++)
        printf("%02X", kdat[t]);
    printf("\n");

    free(kdat);
    free(ctx);

    return 0;
}
