/* DannyNiu/NJF, 2018-03-01. Public Domain. */

#include "bigint.h"
#include <stdio.h>

static egcd640_t egcd;

int main()
{
    long n = 640/32;
    bn640_t p = {
        .w[0] = 0xffffffff,
        .w[1] = 0xffffffff,
        .w[2] = 0xffffffff,
        .w[6] = 0x01,
        .w[7] = 0xffffffff,
    };
    bn640_t a={}, b, c;
    EGCD_SETUP(&egcd);
    
    puts("This program has little-endian assumption.");
    
    for(int iter=0; iter<1000; iter++) {
        fread(&a, 1, 28, stdin);
        bn_egcd(n, (egcd_t *)&egcd, (bn_t *)&b, (bn_t *)&a, (bn_t *)&p);
        bn_mul(n, (bn_t *)&c, (bn_t *)&a, (bn_t *)&b);
        bn_div(n, NULL, (bn_t *)&b, (bn_t *)&c, (bn_t *)&p);
        printf("test case % 8d: ", iter);
        for(long i=8; i--; ) { printf("%08x ", b.w[i]); } puts("");
    }

    return 0;
}
