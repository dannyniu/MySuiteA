/* DannyNiu/NJF, 2018-03-01. Public Domain. */

#include "largeint.h"
#include "../0-datum/endian.h"
#include <stdio.h>

__uint128_t a, b, c, d;
struct intdesc w, x, y, z, nid;
int failed = 0;

void pu32(uint32_t x){ printf(" %08x", x); }

void pu128(__uint128_t x)
{
    putchar('\n');
    pu32(x>>96);
    pu32(x>>64);
    pu32(x>>32);
    pu32(x>> 0);
}

void wrong(const char *s, __uint128_t u, __uint128_t v)
{
    printf("%s wrong: ", s);
    pu128(a);
    pu128(b);
    pu128(u);
    pu128(v);
    putchar('\n');
}

int main()
{
    int msb = BYTE_ORDER == BIG_ENDIAN;
    w = x = y = z = nid = (struct intdesc){
        .len = 4,
        .msb = msb,
        .msw = msb,
    };

    w.p = (void *)&a;
    x.p = (void *)&b;
    y.p = (void *)&c;
    z.p = (void *)&d;
    
    for(int i=0; i<1000*1000; i++) {
        fread(&a, 1, sizeof(a), stdin);
        fread(&b, 1, sizeof(b), stdin);

        li_add(y, w, x);
        li_sub(z, w, x);
        if( c != a+b ) { wrong("add", a+b, c); failed++; }
        if( d != a-b ) { wrong("sub", a-b, d); failed++; }

        li_mul(y, w, x);
        if( c != a*b ) { wrong("mul", a*b, c); failed++; }

        b >>= b%60;
        if( b ) {
            li_div(y, z, w, x);
            if( c != a/b ) { wrong("div:quo", a/b, c); failed++; }
            if( d != a%b ) { wrong("div:rem", a%b, c); failed++; }
            
            li_div(y, nid, w, x);
            if( c != a/b ) { wrong("div:quo", a/b, c); failed++; }
            
            li_div(nid, z, w, x);
            if( d != a%b ) { wrong("div:rem", a%b, d); failed++; }
        }
    }

    printf("%d failed test(s). \n", failed);
    return 0;
}

