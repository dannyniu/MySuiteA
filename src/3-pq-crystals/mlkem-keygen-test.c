/* DannyNiu/NJF, 2024-09-01. Public Domain. */

#include "mlkem-paramset.h"

#include "../test-utils.c.h"

void FixedPRNG(void const *restrict randstr, void *restrict out, size_t len)
{
    static long skip = 0;
    scanhex(out, len, (char *)randstr + skip*2);
    skip += len;
}

int main(int argc, char *argv[])
{
    MLKEM_Priv_Ctx_Hdr_t *ctx;
    CryptoParam_t *param;

    IntPtr lret, t;
    uint8_t *kdat = NULL;
    
    //
    // argv[1]: parameter set.

    if( strcmp(argv[1], "ML-KEM-512") == 0 ) param = MLKEM_512.param;
    if( strcmp(argv[1], "ML-KEM-768") == 0 ) param = MLKEM_768.param;
    if( strcmp(argv[1], "ML-KEM-1024") == 0 ) param = MLKEM_1024.param;

    ctx = calloc(1, tMLKEM(param, bytesCtxPriv));

    //
    // argv[2]: seed.

    MLKEM_Keygen(ctx, param, (GenFunc_t)FixedPRNG, argv[2]);

    //
    // print private key.

    lret = MLKEM_Encode_PrivateKey(ctx, NULL, 0, NULL);
    kdat = frealloc(kdat, lret);
    MLKEM_Encode_PrivateKey(ctx, kdat, lret, NULL);

    for(t=0; t<lret; t++)
        printf("%02X", kdat[t]);
    printf(":");

    //
    // print public key.

    lret = MLKEM_Export_PublicKey(ctx, NULL, 0, NULL);
    kdat = frealloc(kdat, lret);
    MLKEM_Export_PublicKey(ctx, kdat, lret, NULL);

    for(t=0; t<lret; t++)
        printf("%02X", kdat[t]);
    printf("\n");

    free(kdat);
    free(ctx);

    return 0;
}
