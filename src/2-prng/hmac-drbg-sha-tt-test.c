/* DannyNiu/NJF, 2020-11-30. Public Domain. */

#include "hmac-drbg-sha.h"

#include "../test-utils.c.h"

union {
    hmac_drbg_t               x;
    hmac_drbg_hmac_sha1_t     x_hmac_sha1;
    hmac_drbg_hmac_sha256_t   x_hmac_sha256;
    hmac_drbg_hmac_sha384_t   x_hmac_sha384;
} ctx;

iCryptoObj_t hash;
tCryptoObj_t drbg = tHMAC_DRBG;
CryptoParam_t P[2];

typedef uint8_t buffer2048_t[256];
buffer2048_t seed1, seed2, out, ref;

int ret = EXIT_SUCCESS;

void seeds_init(
    size_t nonce_offset, size_t nonce_len,
    size_t prsnl_offset, size_t prsnl_len)
{
    for(size_t i=0; i<sizeof(buffer2048_t); i++)
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

    P[0].template = tHMAC;
    P[0].param = P+1;
    P[1].info = hash;
    P[1].param = NULL;
    
    printf("...... Test Name: %s ......\n", tn);

    ((PInstInitFunc_t)drbg(P, InstInitFunc))(P, &ctx.x, seed1, seedlen1);
    kvlen = ctx.x.prf_outlen * 2;

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
    ((GenFunc_t)drbg(P, GenFunc))(&ctx.x, out, ctx.x.prf_outlen * 2 - 3);
    out[ctx.x.prf_outlen * 2 - 3] ^= 4;
    
    scanhex(ref, ctx.x.prf_outlen * 2, exp2);
    if( memcmp(ref, out, ctx.x.prf_outlen * 2 - 3) )
    {
        printf("Actual output 2 doesn't match: \n");
        fails++;
        printf("Expected Output 2: \n");
        dumphex(ref, ctx.x.prf_outlen * 2 - 3);
        printf("Actual Output 2: \n");
        dumphex(out, ctx.x.prf_outlen * 2 - 3);
    }

    if( !fails ) printf("...... Test Succeeded ......\n");
    else ret = EXIT_FAILURE;
}

void tests_runall()
{
    // NIST example files seems to contain errors.
    //
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
    hash = iSHA1;
    seeds_init(55, 5, 60, 55);
    test_run1(
        "HMAC-DRBG<hash=SHA-1, shortseed>",
        "CD4CAB38 C8AD6571 22BF5D3D 00D0AC9B"
        "13D629BB F660E23E 91006B62 C6543AB1"
        "344D23A3 1AB4CF2C",
        "5A7D3B44 9F481CB3 8DF79AD2 B1FCC01E"
        "57F8135E 8C0B22CD 0630BFB0 127FB540"
        "8C8EFC17 A929896E",
        60, 55);
    test_run1(
        "HMAC-DRBG<hash=SHA-1, longseed>",
        "B9254D8A ACBA43FB DAE6394F 2B3AFC5D"
        "580800BF 28403B60 3638D07D 7966661E"
        "F67B9D39 05F46DB9",
        "B3BD0524 6CBA12A6 4735A4E3 FDE599BC"
        "1BE30F43 9BD06020 8EEA7D71 F9D123DF"
        "47B3CE06 9D98EDE6",
        115, 55); 

    hash = iSHA256;
    seeds_init(55, 8, 63, 55);
    test_run1(
        "HMAC-DRBG<hash=SHA-256, shortseed>",
        "B84007E3 E27F34F9 A7820B7A B59BBEFC"
        "D0C4ACAE DE4B0B36 B147B897 79FD749D"
        "A72B8FEE 92392F0A 9D2D61BF 09A4DFCC"
        "9DE69A16 A5F15022 4C3EF604 2D1521FC",
        "D67B8C17 34F46FA3 F763CF57 C6F9F4F2"
        "DC1089BD 8BC1F6F0 23950BFC 56176352"
        "08C85012 38AD7A44 00DEFEE4 6C640B61"
        "AF77C2D1 A3BFAA90 EDE5D207 406E5403",
        63, 55);
    test_run1(
        "HMAC-DRBG<hash=SHA-256, longseed>",
        "4476C6D1 1FC35D44 09D9032E 453B0F0D"
        "C3314DB8 62CBDB60 9C560220 8D4C88D8"
        "95EF785A 61C2F7B3 6BC596BA 4BA208A5"
        "2C6DC203 636D8F17 87453B85 2B7E49EC",
        "0DD9C855 89F357C3 89D6AF8D E9D734A9"
        "17C771EF 2D8816B9 82596ED1 2DB45D73"
        "4A626808 35C02FDA 66B08E1A 369AE218"
        "F26D5210 AD564248 872D7A28 784159C3",
        118, 55);

    hash = iSHA384;
    seeds_init(111, 12, 123, 111);
    test_run1(
        "HMAC-DRBG<hash=SHA-384, shortseed>",
        "F51761FD 6C4C10BC 6843A51A FE40EFE9"
        "2AC78D7C 2CE62FFA 562E530C 40F165CB"
        "58EA3DF8 447FB5CA 75A4A0C9 7004431E"
        "5279E3F8 A1887F7C 0CE2A9FC 1CCE90B1"
        "E3B8021A 8FFACEE2 66F1D4CB F8589D67"
        "05D0FE7B 6B7EAFC6 70B73EC3 60A5BD35",
        "FF08EED5 0F04D543 FAE5C9C8 FB31D784"
        "89FE82C9 F77F60ED A91A86E5 5EFADB6B"
        "3431BF08 86BC1A63 C44FAD9B 9715C092"
        "6C24AA45 76A94444 23BF6B55 8CEA09FD"
        "BADCE2A5 C05BD480 F8DEF079 75826DAA"
        "53EF71EC 7E28CB38 1D10A7B0 C09A1D15",
        123, 111);
    test_run1(
        "HMAC-DRBG<hash=SHA-384, longseed>",
        "4D2276F7 3EA64903 043B719C A9070167"
        "CDCCCC14 4C0112E4 2C9A74A2 88E692B8"
        "AAFA77E9 7E5BA72B 33F9212F B358347D"
        "A0F9444C 406CB1F5 474077CE B92954A5"
        "01EEBB4F C46C8757 58367BA6 48D99E24"
        "75994FF3 AA4F9C3E FADD63B7 0B67EE71",
        "03AB8BCE 4D1DBBB6 36C5C5B7 E1C58499"
        "FEB1C619 CDD11D35 CD6CF6BB 8F20EF27"
        "B6F5F905 4FF900DB 9EBF7BF3 0ED4DCBB"
        "BC8D5B51 C965EA22 6FFEE2CA 5AB2EFD0"
        "0754DC32 F357BF7A E42275E0 F7704DC4"
        "4E50A522 0AD05AB6 98A22640 AC634829",
        234, 111);
}

int main()
{
    tests_runall();
    return ret;
}
