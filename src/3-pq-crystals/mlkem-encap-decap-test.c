/* DannyNiu/NJF, 2023-11-19. Public Domain. */

#include "mlkem-paramset.h"
#include "../test-utils.c.h"

// 32 is specific to ML-KEM.
// This macro can be altered for other algorithms.
#define SSLEN 32

uint8_t *ss, *ct;
size_t sslen, ctlen;

static void BinRead(void *src, void *dst, size_t copylen)
{
    memcpy(dst, src, copylen);
}

bool test_enc(
    CryptoParam_t *restrict param,
    void const *ek, size_t eklen,
    void const *m, size_t mlen)
{
    bool ret = true;
    void *ctx;

    ctx = calloc(1, tMLKEM(param, bytesCtxPub));
    MLKEM_Decode_PublicKey(ctx, ek, eklen, param);

    if( mlen != 32 ) ret = false; else
    {
        sslen = SSLEN;
        ss = calloc(1, sslen);
        MLKEM_Enc(ctx, ss, &sslen, (GenFunc_t)BinRead, (void *)m);
    }

    MLKEM_Encode_Ciphertext(ctx, NULL, &ctlen);
    ct = calloc(1, ctlen);
    MLKEM_Encode_Ciphertext(ctx, ct, &ctlen);

    // free ct in main later.
    free(ctx);
    return ret;
}

void test_dec(
    CryptoParam_t *restrict param,
    void const *dk, size_t dklen,
    void const *c, size_t clen)
{
    void *ctx;

    ctx = calloc(1, tMLKEM(param, bytesCtxPriv));
    MLKEM_Decode_PrivateKey(ctx, dk, dklen, param);
    MLKEM_Decode_Ciphertext(ctx, c, clen);

    MLKEM_Dec(ctx, NULL, &sslen);
    ss = calloc(1, sslen);
    MLKEM_Dec(ctx, ss, &sslen);

    free(ctx);
}

#define TailorAlloc(id, p)                        \
    id##len = strlen(argv[p]) / 2;                \
    id = calloc(1, id##len);                      \
    scanhex(id, id##len, argv[p]);

int main(int argc, char *argv[])
{
    CryptoParam_t *param;

    int ret = 0;

    //
    // argv[1]: parameter set.

    if( strcmp(argv[1], "ML-KEM-512") == 0 ) param = MLKEM_512.param;
    if( strcmp(argv[1], "ML-KEM-768") == 0 ) param = MLKEM_768.param;
    if( strcmp(argv[1], "ML-KEM-1024")== 0 ) param = MLKEM_1024.param;

    //
    // argv[2]: function.

    if( strcmp(argv[2], "encapsulation") == 0 )
    {
        void *ek, *dk, *c, *k, *m;
        size_t eklen, dklen, clen, klen, mlen;

        TailorAlloc(ek, 3);
        TailorAlloc(dk, 4);
        TailorAlloc(c, 5);
        TailorAlloc(k, 6);
        TailorAlloc(m, 7);

        test_enc(param, ek, eklen, m, mlen);

        if( ctlen != clen || memcmp(ct, c, clen) != 0 )
        {
            printf("Encapsulation Test Failed!\n");
            ret = 1;
        }

        test_dec(param, dk, dklen, c, clen);

        if( sslen != klen || memcmp(ss, k, klen) != 0 )
        {
            printf("Decapsulation Test Failed!\n");
            ret = 1;
        }

        free(ek);
        free(dk);
        free(ct);
        free(c);
        free(k);
        free(m);
    }
    else if( strcmp(argv[2], "decapsulation") == 0 )
    {
        void *dk, *c, *k;
        size_t dklen, clen, klen;

        TailorAlloc(dk, 3);
        TailorAlloc(c, 4);
        TailorAlloc(k, 5);

        test_dec(param, dk, dklen, c, clen);

        if( sslen != klen || memcmp(ss, k, klen) != 0 )
        {
            printf("Decapsulation Validation Failed!\n");
            ret = 1;
        }

        free(dk);
        free(ss);
        free(c);
        free(k);
    }
    else
    {
        printf("Unrecognized Test.\n");
        ret = 1;
    }

    return ret;
}
