/* DannyNiu/NJF, 2018-03-01. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "largeint.h"
#include "../0-datum/endian.h"

static __uint128_t a, b, c, d;
static struct intdesc w, x, y, z, nid;
static int failed = 0;

void pu32(uint32_t arg){ printf(" %08x", arg); }

void pu128(__uint128_t arg)
{
    putchar('\n');
    pu32((uint32_t)(arg>>96));
    pu32((uint32_t)(arg>>64));
    pu32((uint32_t)(arg>>32));
    pu32((uint32_t)(arg>> 0));
}

void wrong(char const *s, __uint128_t u, __uint128_t v)
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
    unsigned short msb = __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__;
    w = x = y = z = nid = (struct intdesc){
        .len = 4,
        .msb = msb,
        .msw = msb,
    };

    w.p = (void *)&a;
    x.p = (void *)&b;
    y.p = (void *)&c;
    z.p = (void *)&d;
    
    for(int i=0; i<200*200; i++) {
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

