/* DannyNiu/NJF, 2023-11-17. Public Domain. */

#include "readhex.c.h"
#include "mldsa-paramset.c"
#include "../test-utils.c.h"

bufvec_t ct[3];

void readhex_callback_verify_test(
    const char *label, void *datptr, size_t datlen)
{
    if( !strcmp(label, "message:") )
        ct[2] = (bufvec_t){ .len = datlen, .dat = datptr };

    if( !strcmp(label, "signature:") )
        ct[1] = (bufvec_t){ .len = datlen, .dat = datptr };

    if( !strcmp(label, "pk:") )
        ct[0] = (bufvec_t){ .len = datlen, .dat = datptr };
}

void readhex_callback_sign_test(
    const char *label, void *datptr, size_t datlen)
{
    if( !strcmp(label, "message:") )
        ct[2] = (bufvec_t){ .len = datlen, .dat = datptr };

    if( !strcmp(label, "signature:") )
        ct[1] = (bufvec_t){ .len = datlen, .dat = datptr };

    if( !strcmp(label, "sk:") )
        ct[0] = (bufvec_t){ .len = datlen, .dat = datptr };
}

bool test_verify(FILE *restrict fp, CryptoParam_t *restrict param)
{
    readhex(fp, readhex_callback_verify_test);

    bool ret;
    IntPtr ctx_size = MLDSA_Decode_PublicKey(
        NULL, ct[0].dat, ct[0].len, param);

    void *ctx = malloc(ctx_size);
    MLDSA_Decode_PublicKey(ctx, ct[0].dat, ct[0].len, param);

    MLDSA_Decode_Signature(ctx, ct[1].dat, ct[1].len);

    if( !MLDSA_Verify(ctx, ct[2].dat, ct[2].len) )
        ret = false;
    else ret = true;

    for(int i=0; i<3; i++)
    {
        free(ct[i].buf);
        ct[i].buf = NULL;
        ct[i].len = 0;
    }

    free(ctx);
    return ret;
}

bool test_sign(FILE *restrict fp, CryptoParam_t *restrict param)
{
    readhex(fp, readhex_callback_sign_test);

    bool ret;
    IntPtr ctx_size = MLDSA_Decode_PrivateKey(
        NULL, ct[0].dat, ct[0].len, param);

    void *ctx = malloc(ctx_size);
    MLDSA_Decode_PrivateKey(ctx, ct[0].dat, ct[0].len, param);

    MLDSA_Sign(ctx, ct[2].dat, ct[2].len, NULL, NULL);
    size_t sig_size;
    MLDSA_Encode_Signature(ctx, NULL, &sig_size);
    void *sig = malloc(sig_size);
    MLDSA_Encode_Signature(ctx, sig, &sig_size);

    if( sig_size != ct[1].len )
    {
        printf("siglen mis-match! sig_size=%zd, ct[2].len=%zd.\n",
               sig_size, ct[1].len);
        ret = false;
    }
    else if( memcmp(sig, ct[1].dat, sig_size) )
    {
        printf("sig mis-match!\n");
        ret = false;
    }
    else ret = true;

    for(int i=0; i<3; i++)
    {
        free(ct[i].buf);
        ct[i].buf = NULL;
        ct[i].len = 0;
    }

    free(ctx);
    free(sig);
    return ret;
}

typedef struct {
    bool (*testsub)(FILE *restrict fp, CryptoParam_t *restrict param);
    char const *path;
    CryptoParam_t *param;
} testvec_t;

testvec_t testvecs[] = {
    { test_sign, "../tests/testvec-fips-203,204-ipd/"
      "Signature Generation -- ML-DSA-44.txt", Param_44 },

    { test_sign, "../tests/testvec-fips-203,204-ipd/"
      "Signature Generation -- ML-DSA-65.txt", Param_65 },

    { test_sign, "../tests/testvec-fips-203,204-ipd/"
      "Signature Generation -- ML-DSA-87.txt", Param_87 },

    { test_verify, "../tests/testvec-fips-203,204-ipd/"
      "Signature Verification -- ML-DSA-44.txt", Param_44 },

    { test_verify, "../tests/testvec-fips-203,204-ipd/"
      "Signature Verification -- ML-DSA-65.txt", Param_65 },

    { test_verify, "../tests/testvec-fips-203,204-ipd/"
      "Signature Verification -- ML-DSA-87.txt", Param_87 },

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
