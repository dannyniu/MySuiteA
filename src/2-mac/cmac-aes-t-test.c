/* DannyNiu/NJF, 2020-11-30. Public Domain. */

#include "cmac-aes.h"

#include "../test-utils.c.h"

union {
    cmac_t          x;
    cmac_aes128_t   x_aes128;
    cmac_aes192_t   x_aes192;
    cmac_aes256_t   x_aes256;
} ctx;

iCryptoObj_t bc;
tCryptoObj_t cmac = tCMAC;
CryptoParam_t P[1];

typedef uint8_t buffer512_t[64];
buffer512_t key, msg, tag, mac;

void test_run1(
    const char *tn,
    const char *k,
    const char *m,
    const char *t)
{
    int fails = 0;
    uint8_t *p;
    size_t kl, ml, tl;
    size_t rl;

    P[0].info = bc;
    P[0].aux = NULL;
    
    printf("...... Test Name: %s ......\n", tn);
    kl = (uint8_t *)scanhex(key, -1, k) - key;
    ml = (uint8_t *)scanhex(msg, -1, m) - msg;
    tl = (uint8_t *)scanhex(tag, -1, t) - tag;

    p = msg;
    ((PKInitFunc_t)cmac(P, KInitFunc))(P, &ctx.x, key, kl);

    while( true )
    {
        rl = myrand() + 1;
        rl = rl > ml ? ml : rl;
        ((UpdateFunc_t)cmac(P, UpdateFunc))(&ctx.x, p, rl);
        ml -= rl;
        p += rl;
        if( !ml ) break;
    }

    ((FinalFunc_t)cmac(P, FinalFunc))(&ctx.x, mac, tl);

    if( memcmp(tag, mac, tl) )
    {
        printf("CMAC computation doesn't match: \n");
        fails++;
        printf("Expected Output 1: \n");
        dumphex(tag, tl);
        printf("Actual Output 1: \n");
        dumphex(mac, tl);
    }
    
    if( !fails ) printf("...... Test Succeeded ......\n");
}

void tests_runall()
{
    bc = iAES128;

    test_run1(
        "CMAC<bc=AES-128>",
        "2B7E1516 28AED2A6 ABF71588 09CF4F3C",
        "",
        "BB1D6929 E9593728 7FA37D12 9B756746");

    test_run1(
        "CMAC<bc=AES-128>",
        "2B7E1516 28AED2A6 ABF71588 09CF4F3C",
        "6BC1BEE2 2E409F96 E93D7E11 7393172A",
        "070A16B4 6B4D4144 F79BDD9D D04A287C");
    
    test_run1(
        "CMAC<bc=AES-128>",
        "2B7E1516 28AED2A6 ABF71588 09CF4F3C",
        "6BC1BEE2 2E409F96 E93D7E11 7393172A"
        "AE2D8A57",
        "7D85449E A6EA19C8 23A7BF78 837DFADE");
    
    test_run1(
        "CMAC<bc=AES-128>",
        "2B7E1516 28AED2A6 ABF71588 09CF4F3C",
        "6BC1BEE2 2E409F96 E93D7E11 7393172A"
        "AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51"
        "30C81C46 A35CE411 E5FBC119 1A0A52EF"
        "F69F2445 DF4F9B17 AD2B417B E66C3710",
        "51F0BEBF 7E3B9D92 FC497417 79363CFE");

    bc = iAES192;
    
    test_run1(
        "CMAC<bc=AES-192>",
        "8E73B0F7 DA0E6452 C810F32B 809079E5"
        "62F8EAD2 522C6B7B",
        "",
        "D17DDF46 ADAACDE5 31CAC483 DE7A9367");

    test_run1(
        "CMAC<bc=AES-192>",
        "8E73B0F7 DA0E6452 C810F32B 809079E5"
        "62F8EAD2 522C6B7B",
        "6BC1BEE2 2E409F96 E93D7E11 7393172A",
        "9E99A7BF 31E71090 0662F65E 617C5184");

    test_run1(
        "CMAC<bc=AES-192>",
        "8E73B0F7 DA0E6452 C810F32B 809079E5"
        "62F8EAD2 522C6B7B",
        "6BC1BEE2 2E409F96 E93D7E11 7393172A"
        "AE2D8A57",
        "3D75C194 ED960704 44A9FA7E C740ECF8");

    test_run1(
        "CMAC<bc=AES-192>",
        "8E73B0F7 DA0E6452 C810F32B 809079E5"
        "62F8EAD2 522C6B7B",
        "6BC1BEE2 2E409F96 E93D7E11 7393172A"
        "AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51"
        "30C81C46 A35CE411 E5FBC119 1A0A52EF"
        "F69F2445 DF4F9B17 AD2B417B E66C3710",
        "A1D5DF0E ED790F79 4D775896 59F39A11");

    bc = iAES256;
    
    test_run1(
        "CMAC<bc=AES-256>",
        "603DEB10 15CA71BE 2B73AEF0 857D7781"
        "1F352C07 3B6108D7 2D9810A3 0914DFF4",
        "",
        "028962F6 1B7BF89E FC6B551F 4667D983");

    test_run1(
        "CMAC<bc=AES-256>",
        "603DEB10 15CA71BE 2B73AEF0 857D7781"
        "1F352C07 3B6108D7 2D9810A3 0914DFF4",
        "6BC1BEE2 2E409F96 E93D7E11 7393172A",
        "28A7023F 452E8F82 BD4BF28D 8C37C35C");

    test_run1(
        "CMAC<bc=AES-256>",
        "603DEB10 15CA71BE 2B73AEF0 857D7781"
        "1F352C07 3B6108D7 2D9810A3 0914DFF4",
        "6BC1BEE2 2E409F96 E93D7E11 7393172A"
        "AE2D8A57",
        "156727DC 0878944A 023C1FE0 3BAD6D93");

    test_run1(
        "CMAC<bc=AES-256>",
        "603DEB10 15CA71BE 2B73AEF0 857D7781"
        "1F352C07 3B6108D7 2D9810A3 0914DFF4",
        "6BC1BEE2 2E409F96 E93D7E11 7393172A"
        "AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51"
        "30C81C46 A35CE411 E5FBC119 1A0A52EF"
        "F69F2445 DF4F9B17 AD2B417B E66C3710",
        "E1992190 549F6ED5 696A2C05 6C315410");
}

int main()
{
    tests_runall();
    return 0;
}
