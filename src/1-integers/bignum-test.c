/* DannyNiu/NJF, 2018-03-01. Public Domain. */

#include "bignum.h"
#include <stdio.h>

#define N 4

int main()
{
    __uint128_t a, b, c, d;
    int failed = 0;
    
    puts("This test program has little-endian assumption.");
    
    for(int i=0; i<1000*1000; i++) {
        fread(&a, 1, sizeof(a), stdin);
        fread(&b, 1, sizeof(b), stdin);

        bn_add(N, (void*)&c, (void*)&a, (void*)&b, 0);
        bn_sub(N, (void*)&d, (void*)&a, (void*)&b, 0);
        if( c != a+b ) { printf("add wrong. \n"); failed++; }
        if( d != a-b ) { printf("sub wrong. \n"); failed++; }

        bn_mul(N, (void*)&c, (void*)&a, (void*)&b);
        if( c != a*b ) { printf("mul wrong. \n"); failed++; }

        b >>= b%60;
        if( b ) {
            bn_div(N, (void*)&c, (void*)&d, (void*)&a, (void*)&b);
            if( c != a/b ) { printf("div:quo wrong. \n"); failed++; }
            if( d != a%b ) { printf("div:rem wrong. \n"); failed++; }
        }
    }

    printf("%d failed test(s). \n", failed);
    return 0;
}

