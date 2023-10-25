/* DannyNiu/NJF, 2023-10-23. Public Domain. */

#include "dilithium-aux.h"
#include "kyber-aux.h"
#include "../1-pq-crystals/m256-codec.h"

#ifndef MLAlgo
#define MLAlgo MLDSA
#endif /* MLAlgo */

#define Q (uint64_t)glue(MLAlgo,_Q)
#define NTT glue(MLAlgo,_NTT)
#define InvNTT glue(MLAlgo,_InvNTT)
#define NttScl glue(MLAlgo,_NttScl)

#include "../2-xof/shake.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

shake_t xof;
module256_t a, b, c, d;
int fails = 0;

bool test_nttscl_method1()
{
    int i, j;

    for(i=0; i<256; i++)
    {
        for(j=0; j<256; j++)
        {
            uint64_t p = (uint64_t)a.r[i] * b.r[j] % Q;
            if( i + j < 256 )
                c.r[i + j] = (c.r[i + j] + p) % Q;
            else c.r[i + j - 256] = (Q + c.r[i + j - 256] - p) % Q;
        }
    }

    NTT(&a);
    NTT(&b);
    //melem_dump_dec(&a);
    //melem_dump_dec(&b);

    NttScl(&d, &a, &b, false);
    //NTT(&c);
    InvNTT(&d);

    //melem_dump_dec(&c);
    //melem_dump_dec(&d);

    if( memcmp(&d, &c, sizeof c) )
        return false;
    else return true;
}

int main(int argc, char *argv[])
{
    int t, i;

    SHAKE128_Init(&xof);
    if( argc >= 2 ) SHAKE_Write(&xof, argv[1], strlen(argv[1]));
    SHAKE_Final(&xof);

    for(t=0; t<32; t++)
    {
        SHAKE_Read(&xof, &a, sizeof a);
        SHAKE_Read(&xof, &b, sizeof b);

        for(i=0; i<256; i++)
        {
            a.r[i] = (uint32_t)a.r[i] % Q;
            b.r[i] = (uint32_t)b.r[i] % Q;
            c.r[i] = d.r[i] = 0;
        }

        test_nttscl_method1();

        if( memcmp(&d, &c, sizeof c) )
        {
            fails++;
        }
    }

    printf("%d of %d test(s) failed\n", fails, t);
    if( fails ) return EXIT_FAILURE;
    else return EXIT_SUCCESS;
}
