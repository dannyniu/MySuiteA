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

typedef uint8_t buffer1024_t[128];
buffer1024_t seed1, seed2, out, ref;

int ret = EXIT_SUCCESS;

void seeds_init(
    size_t nonce_offset, size_t nonce_len,
    size_t prsnl_offset, size_t prsnl_len)
{
    for(size_t i=0; i<sizeof(buffer1024_t); i++)
    {
        seed1[i] = i;
        seed2[i] = i + 0x80;
    }

    for(size_t i=0; i<nonce_len; i++)
    {
        seed1[i + nonce_offset] = i + 0x20;
    }

    for(size_t i=0; i<prsnl_len; i++)
    {
        seed1[i + prsnl_offset] = i + 0x40;
        seed2[i + nonce_offset] = i + 0x60;
    }
}

void test_run1(
    char const *tn,
    char const *exp1,
    char const *exp2,
    size_t seedlen1,
    size_t seedlen2)
{
    int fails = 0;
    size_t kvlen;

    P[0].info = bc;
    P[0].param = NULL;

    printf("...... Test Name: %s ......\n", tn);

    ((PInstInitFunc_t)drbg(P, InstInitFunc))(P, &ctx.x, seed1, seedlen1);
    kvlen = ctx.x.bc_blksize + ctx.x.bc_keysize;

    ((ReseedFunc_t)drbg(P, ReseedFunc))(&ctx.x, seed2, seedlen2);

    scanhex(ref, kvlen, exp1);
    if( memcmp(ref, ((uint8_t *)&ctx.x + ctx.x.offset_k), kvlen) )
    {
        printf("Actual output 1 doesn't match: \n");
        fails++;
        printf("Expected Output 1: \n");
        dumphex(ref, kvlen);
        printf("Actual Output 1: \n");
        dumphex(
            ((uint8_t *)&ctx.x + ctx.x.offset_k),
            kvlen);
    }

    ((PInstInitFunc_t)drbg(P, InstInitFunc))(P, &ctx.x, seed1, seedlen1);

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
    // The 1st expected output comes from
    // the internal state after the 1st reseed
    // in the example values for which:
    // - PredictionResistance   == true,
    // - AdditionalInput        == null,
    // - PersonalizationString  == null/<t>.
    //
    // The 2nd expected output comes from
    // the output generated from the 1st call to
    // the instance for which:
    // - PredicationResistance  == false,
    // - AdditionalInput        == null,
    // - PersonalizationString  == null/<t>.
    //
    bc = iAES128;
    seeds_init(32, 8, 40, 32);
    test_run1(
        "CTR-DRBG<bc=AES-128, df=true, shortseed>",
        "64478E87 F0FB4CC7 E21589E8 C77440FA"
        "D6DF63C3 3E7A0C20 F57D3D07 DDA7C97B",
        "8CF59C8C F6888B96 EB1C1E3E 79D82387"
        "AF08A9E5 FF75E23F 1FBCD455 9B6B997E",
        40, 32);
    test_run1(
        "CTR-DRBG<bc=AES-128, df=true, longseed>",
        "D90A52B5 3522F92B 2A325EF4 AB2704C4"
        "AA703DDA CB13C32C D5A82ACB 91EAFB0D",
        "18FDEFBD C43D7A36 D5D6D862 205765D1"
        "D701C9F2 37007030 DF1B8E70 EE4EEE29",
        72, 64);

    bc = iAES192;
    seeds_init(40, 12, 52, 40);
    test_run1(
        "CTR-DRBG<bc=AES-192, df=true, shortseed>",
        "F68633C5 B5A95CD6 C849006F 39F5E65F"
        "700DD541 F46BA592 C9431E33 795EF5D8"
        "71994A56 E68770FD",
        "1A646BB1 D38BD2AE A30CF5C5 D812A624"
        "B50D3ECA 99E508B2 5B5448A8 B96C0F2E",
        52, 40);
    test_run1(
        "CTR-DRBG<bc=AES-192, df=true, longseed>",
        "34E325F2 01C54A17 6145CC0E F46EF00E"
        "5ED6B09C B381472B 257408CD 32FB1263"
        "17D6FB71 9DFEEC65",
        "E231244B 3235B085 C8160442 4357E852"
        "01E3828B 5C455686 79A5555F 867AAC8C",
        92, 80);

    bc = iAES256;
    seeds_init(48, 16, 64, 48);
    test_run1(
        "CTR-DRBG<bc=AES-256, df=true, shortseed>",
        "1798C0DF 09696A46 1946FE6D 687D8CC8"
        "3FEEF122 F3BBC5F2 9DAC8510 F34AF015"
        "0BF3344D F529276B 0D5BBC83 9BD3656A",
        "E686DD55 F758FD91 BA7CB726 FE0B573A"
        "180AB674 39FFBDFE 5EC28FB3 7A16A53B",
        64, 48);
    test_run1(
        "CTR-DRBG<bc=AES-256, df=true, longseed>",
        "41EE7860 CDD8CA72 E54157DD 5B0C3946"
        "F5472B12 FE6A3D9E 816F9E24 794A5D9F"
        "2441A4FE 033C3F0A 2E0C64BB 0CFFD04D",
        "99BB703C DD820609 903F1241 EA856E27"
        "A54C2B75 EEA7775B 68093FCD 47B52E7F",
        112, 96);
}

int main()
{
    tests_runall();
    return ret;
}
