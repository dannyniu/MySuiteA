/* DannyNiu/NJF, 2023-11-19. Public Domain. */

#include "readhex.c.h"
#include "mlkem-paramset.c"
#include "../test-utils.c.h"

bufvec_t ct[4];

void readhex_callback_enc_test(
    const char *label, void *datptr, size_t datlen)
{
    if( !strcmp(label, "m:") )
        ct[3] = (bufvec_t){ .len = datlen, .dat = datptr };

    if( !strcmp(label, "k:") )
        ct[2] = (bufvec_t){ .len = datlen, .dat = datptr };

    if( !strcmp(label, "c:") )
        ct[1] = (bufvec_t){ .len = datlen, .dat = datptr };

    if( !strcmp(label, "ek:") )
        ct[0] = (bufvec_t){ .len = datlen, .dat = datptr };
}

void readhex_callback_dec_test(
    const char *label, void *datptr, size_t datlen)
{
    if( !strcmp(label, "k:") )
        ct[2] = (bufvec_t){ .len = datlen, .dat = datptr };

    if( !strcmp(label, "c:") )
        ct[1] = (bufvec_t){ .len = datlen, .dat = datptr };

    if( !strcmp(label, "dk:") )
        ct[0] = (bufvec_t){ .len = datlen, .dat = datptr };
}

static void BinRead(void *src, void *dst, size_t copylen)
{
    memcpy(dst, src, copylen);
}

bool test_enc(FILE *restrict fp, CryptoParam_t *restrict param)
{
    readhex(fp, readhex_callback_enc_test);

    bool ret = true;
    IntPtr ctx_size = MLKEM_Decode_PublicKey(
        NULL, ct[0].dat, ct[0].len, param);

    void *ctx = malloc(ctx_size);
    MLKEM_Decode_PublicKey(ctx, ct[0].dat, ct[0].len, param);

    uint8_t ss[32];
    size_t sslen = 32;
    MLKEM_Enc(ctx, ss, &sslen, BinRead, ct[3].buf);

    if( sslen != ct[2].len || memcmp(ss, ct[2].dat, sslen) )
        ret = false;

    size_t ctlen;
    MLKEM_Encode_Ciphertext(ctx, NULL, &ctlen);
    void *ciphertext = malloc(ctlen);
    MLKEM_Encode_Ciphertext(ctx, ciphertext, &ctlen);

    if( ctlen != ct[1].len || memcmp(ct[1].dat, ciphertext, ctlen) )
        ret = false;

    for(int i=0; i<4; i++)
    {
        free(ct[i].buf);
        ct[i].buf = NULL;
        ct[i].len = 0;
    }

    free(ctx);
    free(ciphertext);
    return ret;
}

bool test_dec(FILE *restrict fp, CryptoParam_t *restrict param)
{
    readhex(fp, readhex_callback_dec_test);

    bool ret = true;

    IntPtr ctx_size = MLKEM_Decode_PrivateKey(
        NULL, ct[0].dat, ct[0].len, param);
    void *ctx = malloc(ctx_size);
    MLKEM_Decode_PrivateKey(ctx, ct[0].dat, ct[0].len, param);

    MLKEM_Decode_Ciphertext(ctx, ct[1].dat, ct[1].len);

    uint8_t ss[32];
    size_t sslen = 32;
    MLKEM_Dec(ctx, ss, &sslen);

    if( sslen != ct[2].len || memcmp(ss, ct[2].dat, sslen) )
        ret = false;

    for(int i=0; i<3; i++)
    {
        free(ct[i].buf);
        ct[i].buf = NULL;
        ct[i].len = 0;
    }

    free(ctx);
    return ret;
}

typedef struct {
    bool (*testsub)(FILE *restrict fp, CryptoParam_t *restrict param);
    char const *path;
    CryptoParam_t *param;
} testvec_t;

testvec_t testvecs[] = {
    { test_dec, "../tests/testvec-fips-203,204-ipd/"
      "Decapsulation -- ML-KEM-512.txt", Param_K512 },

    { test_dec, "../tests/testvec-fips-203,204-ipd/"
      "Decapsulation -- ML-KEM-768.txt", Param_K768 },

    { test_dec, "../tests/testvec-fips-203,204-ipd/"
    "Decapsulation -- ML-KEM-1024.txt", Param_K1024 },

    { test_enc, "../tests/testvec-fips-203,204-ipd/"
      "Encapsulation -- ML-KEM-512.txt", Param_K512 },

    { test_enc, "../tests/testvec-fips-203,204-ipd/"
      "Encapsulation -- ML-KEM-768.txt", Param_K768 },

    { test_enc, "../tests/testvec-fips-203,204-ipd/"
    "Encapsulation -- ML-KEM-1024.txt", Param_K1024 },

    {0},
};

int main()
{
    int ret = EXIT_SUCCESS;
    FILE *fp;

    testvec_t *testvec = testvecs;

    while( testvec->testsub )
    {
        fp = fopen(testvec->path, "r");
        if( !testvec->testsub(fp, testvec->param) )
        {
            printf("Test vector failed: %s\n", testvec->path);
            ret = EXIT_FAILURE;
        }
        fclose(fp);
        testvec++;
    }

    return ret;
}
