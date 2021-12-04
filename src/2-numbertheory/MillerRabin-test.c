/* DannyNiu/NJF, 2021-02-16. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "MillerRabin.h"
#include "../2-xof/gimli-xof.h"

static VLONG_T(9) p256, n256, c25519;
static VLONG_T(33) rp, t1, t2, t3;
static gimli_xof_t gx;

int main(int argc, char *argv[])
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

    rp.c = 33;
    rp.v[32] = 0;
    rp.v[31] = 0xf1700c2d;
    rp.v[30] = 0x21321a9e;
    rp.v[29] = 0x9dcae628;
    rp.v[28] = 0x01c50cde;
    rp.v[27] = 0x3db2baec;
    rp.v[26] = 0x6fca668e;
    rp.v[25] = 0x047e1655;
    rp.v[24] = 0x6ae2f42e;
    rp.v[23] = 0xa02fbadf;
    rp.v[22] = 0xb2976c75;
    rp.v[21] = 0xddda466c;
    rp.v[20] = 0xeb411c42;
    rp.v[19] = 0x5b43e784;
    rp.v[18] = 0xe6fd4635;
    rp.v[17] = 0x19647c21;
    rp.v[16] = 0xb6001281;
    rp.v[15] = 0x9c9ed1e8;
    rp.v[14] = 0x6d82fd5f;
    rp.v[13] = 0x6eccdadd;
    rp.v[12] = 0x07590e39;
    rp.v[11] = 0xac58fffc;
    rp.v[10] = 0x0b53e2e8;
    rp.v[9] = 0x2f1b9c4e;
    rp.v[8] = 0x6263607f;
    rp.v[7] = 0xea75e62b;
    rp.v[6] = 0x7954c45a;
    rp.v[5] = 0x8c176500;
    rp.v[4] = 0xfca2345a;
    rp.v[3] = 0xebe0bbe1;
    rp.v[2] = 0xb0a541af;
    rp.v[1] = 0xb390d11a;
    rp.v[0] = 0x145dd4b7;

    Gimli_XOF_Init(&gx);
    Gimli_XOF_Write(&gx, "Hello World!", 12);
    if( argc >= 2 )
        Gimli_XOF_Write(&gx, argv[1], strlen(argv[1]));
    Gimli_XOF_Final(&gx);

    t1.c = t2.c = t3.c = 9;
    
    printf("%d - tested{p256}\n", MillerRabin(
               (void *)&p256, 12, (void *)&t1, (void *)&t2, (void *)&t3,
               (GenFunc_t)Gimli_XOF_Read, &gx));
    
    printf("%d - tested{n256}\n", MillerRabin(
               (void *)&n256, 12, (void *)&t1, (void *)&t2, (void *)&t3,
               (GenFunc_t)Gimli_XOF_Read, &gx));
    
    printf("%d - tested{c25519}\n", MillerRabin(
               (void *)&c25519, 12, (void *)&t1, (void *)&t2, (void *)&t3,
               (GenFunc_t)Gimli_XOF_Read, &gx));

    t1.c = t2.c = t3.c = 33;

    printf("%d - tested{rp}\n", MillerRabin(
               (void *)&rp, 12, (void *)&t1, (void *)&t2, (void *)&t3,
               (GenFunc_t)Gimli_XOF_Read, &gx));

    return 0;
}
