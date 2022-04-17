/* DannyNiu/NJF, 2020-11-30. Public Domain. */

#include "ctr-drbg-aes.h"

#include "../test-utils.c.h"

union {
    ctr_drbg_t          x;
    ctr_drbg_aes128_t   x_aes128;
    ctr_drbg_aes192_t   x_aes192;
    ctr_drbg_aes256_t   x_aes256;
} ctx;

iCryptoObj_t bc;
tCryptoObj_t drbg = tCTR_DRBG;
CryptoParam_t P[1];

typedef uint8_t buffer512_t[64];
buffer512_t seed1, seed2, out, ref;

int ret = EXIT_SUCCESS;

void seeds_init()
{
    for(size_t i=0; i<sizeof(buffer512_t); i++)
    {
        seed1[i] = i;
        seed2[i] = i + 0x80;
    }
}

void test_run1(const char *tn, const char *exp1, const char *exp2)
{
    size_t seedlen;
    int fails = 0;

    P[0].info = bc;
    P[0].param = NULL;
    seedlen = drbg(P, seedBytes);

    printf("...... Test Name: %s ......\n", tn);

    ((PInstInitFunc_t)drbg(P, InstInitFunc))(P, &ctx.x, seed1, seedlen);

    ((ReseedFunc_t)drbg(P, ReseedFunc))(&ctx.x, seed2, seedlen);

    scanhex(ref, seedlen, exp1);
    if( memcmp(ref, ((uint8_t *)&ctx.x + ctx.x.offset_k), seedlen) )
    {
        printf("Actual output 1 doesn't match: \n");
        fails++;
        printf("Expected Output 1: \n");
        dumphex(ref, seedlen);
        printf("Actual Output 1: \n");
        dumphex(
            ((uint8_t *)&ctx.x + ctx.x.offset_k),
            seedlen);
    }

    ((PInstInitFunc_t)drbg(P, InstInitFunc))(P, &ctx.x, seed1, seedlen);

    // -3 to test incomplete blocks' code path
    ((GenFunc_t)drbg(P, GenFunc))(&ctx.x, out, 32 - 3);
    out[29] ^= 4;

    scanhex(ref, 32, exp2);
    if( memcmp(ref, out, 32 - 3) )
    {
        printf("Actual output 2 doesn't match: \n");
        fails++;
        printf("Expected Output 2: \n");
        dumphex(ref, 32 - 3);
        printf("Actual Output 2: \n");
        dumphex(out, 32 - 3);
    }

    if( !fails ) printf("...... Test Succeeded ......\n");
    else ret = EXIT_FAILURE;
}

void tests_runall()
{
    seeds_init();

    // NIST example files seems to contain errors.
    //
    // The 1st expected output comes from
    // the internal state after the 1st reseed
    // in the example values for which:
    // - PredictionResistance   == true,
    // - AdditionalInput        == null,
    // - PersonalizationString  == null.
    //
    // The 2nd expected output comes from
    // the output generated from the 1st call to
    // the instance for which:
    // - PredicationResistance  == false,
    // - AdditionalInput        == null,
    // - PersonalizationString  == null.
    //
    bc = iAES128;
    test_run1(
        "CTR-DRBG<bc=AES-128, df=false>",
        "96077D4C 1BB00D60 CCDB6CCC 3698E424"
        "9582C504 85EA473C A9E4AB17 FA93A387",
        "1686FFCF 9F358BE7 4452E647 BA156AAB"
        "05135797 117FD1AB 317D318C 660E3D18");

    bc = iAES192;
    test_run1(
        "CTR-DRBG<bc=AES-192, df=false>",
        "8161FBBD E8F1E27D 7696E672 3BCBE405"
        "541585A4 082F3793 8B425703 7D0AEE86"
        "C8FD24DA FEB646C7",
        "01E0793E 6C7464FA FE1F6CF9 B7466A8A"
        "C4841737 9CBAA104 13DBCD98 E1977019");

    bc = iAES256;
    test_run1(
        "CTR-DRBG<bc=AES-256, df=false>",
        "8694D2A0 C9900AD9 41DC1F75 8862F4AA"
        "E6EEBCB7 58BE52EE 48041C47 06216378"
        "A5CB2E85 CB3B5FD9 782CEB70 7E4C510E",
        "06155023 4D158C5E C95595FE 04EF7A25"
        "767F2E24 CC2BC479 D09D86DC 9ABCFDE7");
}

int main()
{
    tests_runall();
    return ret;
}
