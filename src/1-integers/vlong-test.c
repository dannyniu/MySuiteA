/* DannyNiu/NJF, 2020-12-27. Public Domain. */

#include <stdio.h>
#include "vlong.h"

__uint128_t vlong2huge(vlong_t *x)
{
    return
        ((__uint128_t)x->v[3] << 96) |
        ((__uint128_t)x->v[2] << 64) |
        ((__uint128_t)x->v[1] << 32) |
        ((__uint128_t)x->v[0] <<  0);
}

__uint128_t a, b, c, d;
VLONG_T(4) u, v, w, x;
static long failed = 0;

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
    u.c = v.c = w.c = x.c = 4;

    for(long n=0; n<200*200; n++)
    {
        fread(&a, 1, sizeof(a), stdin);
        fread(&b, 1, sizeof(b), stdin);

        for(int i=0; i<4; i++)
        {
            u.v[i] = a >> (i * 32);
            v.v[i] = b >> (i * 32);
        }

        vlong_addv((vlong_t *)&w, (vlong_t *)&u, (vlong_t *)&v);
        vlong_subv((vlong_t *)&x, (vlong_t *)&u, (vlong_t *)&v);
        
        if( (c = vlong2huge((vlong_t *)&w)) != a + b )
            wrong("add", a+b, c), failed++;
        
        if( (d = vlong2huge((vlong_t *)&x)) != a - b )
            wrong("sub", a-b, d), failed++;

        vlong_mulv((vlong_t *)&w, (vlong_t *)&u, (vlong_t *)&v);
        
        if( (c = vlong2huge((vlong_t *)&w)) != a * b )
            wrong("mul", a*b, c), failed++;
        
        b >>= b % 60;
        if( !b ) continue;
        for(int i=0; i<4; i++)
            v.v[i] = b >> (i * 32);

        vlong_divv((vlong_t *)&x, (vlong_t *)&w, (vlong_t *)&u, (vlong_t *)&v);
        
        if( (c = vlong2huge((vlong_t *)&x)) != a % b )
            wrong("rem", a % b, c), failed++;

        if( (d = vlong2huge((vlong_t *)&w)) != a / b )
            wrong("quo", a / b, d), failed++;

        for(int i=0; i<4; i++) x.v[i] = u.v[i];
        vlong_remv_inplace((vlong_t *)&x, (vlong_t *)&v);
        
        if( (c = vlong2huge((vlong_t *)&x)) != a % b )
            wrong("irem", a % b, c), failed++;
    }
    
    printf("%ld failed test(s). \n", failed);
    return 0;
}
