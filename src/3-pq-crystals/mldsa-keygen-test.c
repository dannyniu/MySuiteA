/* DannyNiu/NJF, 2024-09-01. Public Domain. */

#include "mldsa-paramset.h"

#include "../test-utils.c.h"

void FixedPRNG(void const *restrict randstr, void *restrict out, size_t len)
{
    scanhex(out, len, randstr);
}

int main(int argc, char *argv[])
{
    MLDSA_Priv_Ctx_Hdr_t *ctx;
    CryptoParam_t *param;

    IntPtr lret, t;
    uint8_t *kdat = NULL;

    assert( argc == 3 );

    //
    // argv[1]: parameter set.

    if( strcmp(argv[1], "ML-DSA-44") == 0 ) param = MLDSA44.param;
    if( strcmp(argv[1], "ML-DSA-65") == 0 ) param = MLDSA65.param;
    if( strcmp(argv[1], "ML-DSA-87") == 0 ) param = MLDSA87.param;

    ctx = calloc(1, tMLDSA(param, bytesCtxPriv));

    //
    // argv[2]: seed.

    MLDSA_Keygen(ctx, param, (GenFunc_t)FixedPRNG, argv[2]);

    //
    // print private key.

    lret = MLDSA_Encode_PrivateKey(ctx, NULL, 0, NULL);
    kdat = frealloc(kdat, lret);
    MLDSA_Encode_PrivateKey(ctx, kdat, lret, NULL);

    for(t=0; t<lret; t++)
        printf("%02X", kdat[t]);
    printf(":");

    //
    // print public key.

    lret = MLDSA_Export_PublicKey(ctx, NULL, 0, NULL);
    kdat = frealloc(kdat, lret);
    MLDSA_Export_PublicKey(ctx, kdat, lret, NULL);

    for(t=0; t<lret; t++)
        printf("%02X", kdat[t]);
    printf("\n");

    free(kdat);
    free(ctx);

    return 0;
}
