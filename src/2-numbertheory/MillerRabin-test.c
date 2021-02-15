/* DannyNiu/NJF, 2021-02-16. Public Domain. */

#include "MillerRabin.h"
#include "../2-xof/gimli-xof.h"

#include <stdio.h>

static VLONG_T(9) p256, n256, c25519, t1, t2, t3;
static gimli_xof_t gx;

int main()
{
    p256.c = 9;
    p256.v[7] = -1;
    p256.v[6] = 1;
    p256.v[2] = -1;
    p256.v[1] = -1;
    p256.v[0] = -1;

    n256.c = 9;
    n256.v[7] = -1;
    n256.v[5] = -1;
    n256.v[4] = -1;
    n256.v[3] = 0xBCE6FAAD;
    n256.v[2] = 0xA7179E84;
    n256.v[1] = 0xF3B9CAC2;
    n256.v[0] = 0xFC632551;

    c25519.c = 9;
    c25519.v[7] = 0x7fffffff;
    c25519.v[6] = 0xffffffff;
    c25519.v[5] = 0xffffffff;
    c25519.v[4] = 0xffffffff;
    c25519.v[3] = 0xffffffff;
    c25519.v[2] = 0xffffffff;
    c25519.v[1] = 0xffffffff;
    c25519.v[0] = 0xffffffed;

    t1.c = t2.c = t3.c = 9;

    Gimli_XOF_Init(&gx);
    Gimli_XOF_Write(&gx, "Hello World!", 12);
    Gimli_XOF_Final(&gx);

    printf("%d\n", MillerRabin(
               (void *)&p256, 12, (void *)&t1, (void *)&t2, (void *)&t3,
               (GenFunc_t)Gimli_XOF_Read, &gx));
    
    printf("%d\n", MillerRabin(
               (void *)&n256, 12, (void *)&t1, (void *)&t2, (void *)&t3,
               (GenFunc_t)Gimli_XOF_Read, &gx));
    
    printf("%d\n", MillerRabin(
               (void *)&c25519, 12, (void *)&t1, (void *)&t2, (void *)&t3,
               (GenFunc_t)Gimli_XOF_Read, &gx));

    return 0;
}
