/* DannyNiu/NJF, 2022-04-14. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "shake.h"

#include "../test-utils.c.h"

#define HASH_LEN 64

static const struct {
    iCryptoObj_t xof;
    size_t DataLen, DigestLen;
    const char *N, *S, *ref;
} testvecs[] = {
    {
        iSHAKE128, 4, 32,
        "",
        "Email Signature",
        "C1 C3 69 25 B6 40 9A 04 F1 B5 04 FC BC A9 D8 2B"
        "40 17 27 7C B5 ED 2B 20 65 FC 1D 38 14 D5 AA F5",
    },
    {
        iSHAKE128, 200, 32,
        "",
        "Email Signature",
        "C5 22 1D 50 E4 F8 22 D9 6A 2E 88 81 A9 61 42 0F"
        "29 4B 7B 24 FE 3D 20 94 BA ED 2C 65 24 CC 16 6B",
    },
    {
        iSHAKE256, 4, 64,
        "",
        "Email Signature",
        "D0 08 82 8E 2B 80 AC 9D 22 18 FF EE 1D 07 0C 48"
        "B8 E4 C8 7B FF 32 C9 69 9D 5B 68 96 EE E0 ED D1"
        "64 02 0E 2B E0 56 08 58 D9 C0 0C 03 7E 34 A9 69"
        "37 C5 61 A7 4C 41 2B B4 C7 46 46 95 27 28 1C 8C",
    },
    {
        iSHAKE256, 200, 64,
        "",
        "Email Signature",
        "07 DC 27 B1 1E 51 FB AC 75 BC 7B 3C 1D 98 3E 8B"
        "4B 85 FB 1D EF AF 21 89 12 AC 86 43 02 73 09 17"
        "27 F4 2B 17 ED 1D F6 3E 8E C1 18 F0 4B 23 63 3C"
        "1D FB 15 74 C8 FB 55 CB 45 DA 8E 25 AF B0 92 BB",
    },
    { 0 }
}, *testptr = testvecs;

int main()
{
    cshake_t sh;
    uint8_t bin[HASH_LEN];
    uint8_t ref[HASH_LEN];
    uint8_t msg[200];
    int fails = 0;

    bufvec_t bv[2];
    size_t t;

    for(t=0; t<sizeof(msg); t++) msg[t] = (uint8_t)t;

    while( testptr->xof )
    {
        bv[0].len = strlen(testptr->N);
        bv[1].len = strlen(testptr->S);
        bv[0].dat = testptr->N;
        bv[1].dat = testptr->S;
        
        INIT_FUNC(testptr->xof)(&sh);
        XCTRL_FUNC(testptr->xof)(
            &sh, SHAKE_cSHAKE_customize,
            bv, 2, 0);

        WRITE_FUNC(testptr->xof)(&sh, msg, testptr->DataLen);
        XFINAL_FUNC(testptr->xof)(&sh);
        READ_FUNC(testptr->xof)(&sh, bin, testptr->DigestLen);
        
        scanhex(ref, testptr->DigestLen, testptr->ref);
        if( memcmp(bin, ref, testptr->DigestLen) )
        {
            fails++;
            printf("test %ld failed!\n", (long)(testptr - testvecs));
        }

        testptr++;
    }

    if( fails ) return EXIT_FAILURE; else
    {
        printf("All tests passed.\n");
        return EXIT_SUCCESS;
    }
}
