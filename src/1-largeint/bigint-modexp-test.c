/* DannyNiu/NJF, 2018-03-07. Public Domain. */

#include "bigint.h"
#include <stdio.h>

int main()
{
    egcd640_t egcd; mont640_t mont; bn640_t tmp;
    
    long n = 640/32;
    bn640_t p = {
        .w[0] = 0xffffffff,
        .w[1] = 0xffffffff,
        .w[2] = 0xffffffff,
        .w[6] = 1,
        .w[7] = 0xffffffff,
    };
    bn640_t a={}, b={}, c={}, out;

    EGCD_SETUP(&egcd);
    MONT_SETUP(&mont);
    
    bn_mont_set_N(n, (void *)&mont, (void *)&egcd, (void *)&p);

    fputs("This test program has little-endian assumption.\n", stderr);
    //freopen("/dev/urandom", "rb", stdin);

    for(int iter=0; iter<100; iter++) {
        fread(&a, 1, 30, stdin);
        bn_mont_convert(n, (void *)&mont, (void *)&b, (void *)&a);

        fread(&c, 1, 5, stdin);
        bn_mont_modexp(n, (void *)&mont, (void *)&out, (void *)&b, (void *)&c, (void *)&tmp);
        bn_mont_REDC(n, (void *)&mont, (void *)&out, (void *)&out);

        for(int i=8; i--; ) { printf("%08X", out.w[i]); }
        printf("-");
        printf("m(");
        for(int i=8; i--; ) { printf("%08X", a.w[i]); } printf(",");
        for(int i=2; i--; ) { printf("%08X", c.w[i]); } printf(",");
        printf("p)\n");
    }

    return 0;
}
