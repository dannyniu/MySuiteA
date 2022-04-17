/* DannyNiu/NJF, 2021-07-22. Public Domain. */

#include "kmac.h"

#include "../test-utils.c.h"

kmac_t ctx;

iCryptoObj_t kmac;

typedef uint8_t buffer2048_t[256];
buffer2048_t key, msg, tag, mac;

int ret = EXIT_SUCCESS;

void test_run1(
    const char *tn,
    const char *s,
    size_t klen,
    size_t ml,
    size_t L,
    const char *t)
{
    int fails = 0;
    uint8_t *p;
    size_t tl;
    size_t rl;

    printf("...... Test Name: %s ......\n", tn);
    tl = (uint8_t *)scanhex(tag, -1, t) - tag;

    p = msg;
    if( s )
    {
        bufvec_t bv[2] = {
            [0] = { .len = strlen(s), .dat = s },
            [1] = { .len = klen, .dat = key } };

        XCTRL_FUNC(kmac)(
            &ctx, KMAC_KInit_WithS,
            bv, 2, 0);
    }
    else KINIT_FUNC(kmac)(&ctx, key, klen);

    while( true )
    {
        rl = myrand() + 1;
        rl = rl > ml ? ml : rl;
        UPDATE_FUNC(kmac)(&ctx, p, rl);
        ml -= rl;
        p += rl;
        if( !ml ) break;
    }

    FINAL_FUNC(kmac)(&ctx, mac, L);

    if( memcmp(tag, mac, L) )
    {
        printf("KMAC computation doesn't match: \n");
        fails++;
        printf("Expected Output 1: \n");
        dumphex(tag, tl);
        printf("Actual Output 1: \n");
        dumphex(mac, tl);
    }

    if( !fails ) printf("...... Test Succeeded ......\n");
    else ret = EXIT_FAILURE;
}

void tests_runall()
{
    size_t t;
    for(t=0x40; t<0x60; t++) key[t - 0x40] = t;
    for(t=0; t<sizeof(msg); t++) msg[t] = t;

    kmac = iKMAC128;

    test_run1(
        "KMAC-128: short msg, S=null",
        "",
        32, 4, 32,
        "E5 78 0B 0D 3E A6 F7 D3 A4 29 C5 70 6A A4 3A 00"
        "FA DB D7 D4 96 28 83 9E 31 87 24 3F 45 6E E1 4E");

    test_run1(
        "KMAC-128: short msg, S=<t>",
        "My Tagged Application",
        32, 4, 32,
        "3B 1F BA 96 3C D8 B0 B5 9E 8C 1A 6D 71 88 8B 71"
        "43 65 1A F8 BA 0A 70 70 C0 97 9E 28 11 32 4A A5");

    test_run1(
        "KMAC-128: long msg, S=<t>",
        "My Tagged Application",
        32, 200, 32,
        "1F 5B 4E 6C CA 02 20 9E 0D CB 5C A6 35 B8 9A 15"
        "E2 71 EC C7 60 07 1D FD 80 5F AA 38 F9 72 92 30");

    kmac = iKMAC256;

    test_run1(
        "KMAC-256: short msg, S=<t>",
        "My Tagged Application",
        32, 4, 64,
        "20 C5 70 C3 13 46 F7 03 C9 AC 36 C6 1C 03 CB 64"
        "C3 97 0D 0C FC 78 7E 9B 79 59 9D 27 3A 68 D2 F7"
        "F6 9D 4C C3 DE 9D 10 4A 35 16 89 F2 7C F6 F5 95"
        "1F 01 03 F3 3F 4F 24 87 10 24 D9 C2 77 73 A8 DD");

    test_run1(
        "KMAC-256: long msg, S=null",
        "",
        32, 200, 64,
        "75 35 8C F3 9E 41 49 4E 94 97 07 92 7C EE 0A F2"
        "0A 3F F5 53 90 4C 86 B0 8F 21 CC 41 4B CF D6 91"
        "58 9D 27 CF 5E 15 36 9C BB FF 8B 9A 4C 2E B1 78"
        "00 85 5D 02 35 FF 63 5D A8 25 33 EC 6B 75 9B 69");

    test_run1(
        "KMAC-256: long msg, S=<t>",
        "My Tagged Application",
        32, 200, 64,
        "B5 86 18 F7 1F 92 E1 D5 6C 1B 8C 55 DD D7 CD 18"
        "8B 97 B4 CA 4D 99 83 1E B2 69 9A 83 7D A2 E4 D9"
        "70 FB AC FD E5 00 33 AE A5 85 F1 A2 70 85 10 C3"
        "2D 07 88 08 01 BD 18 28 98 FE 47 68 76 FC 89 65");
}

int main()
{
    tests_runall();
    return ret;
}
