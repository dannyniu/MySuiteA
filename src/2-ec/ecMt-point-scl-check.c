/* DannyNiu/NJF, 2022-04-28. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "ecMt.h"
#include "../1-integers/vlong-dat.h"

#include "../0-exec/struct-delta.c.h"
// #include "../1-integers/vlong-dbg.c.h"
void printl(void *);
void randoml(void *);

#include "../test-utils.c.h"

typedef ECMT_OPCTX_T(255) ecMt255_opctx_t;

int main(void)
{
    ecMt255_opctx_t opctx;
    VLONG_T(11) k;
    VLONG_T(11) Q;
    uint8_t H[32];
    
    ecMt_opctx_init((ecMt_opctx_t *)&opctx, 255);
    k.c = Q.c = 11;

    scanhex(H, 32,
            "a546e36bf0527c9d3b16154b82465edd"
            "62144c0ac1fc5a18506a2244ba449ac4");
    H[0] &= 248;
    H[31] &= 127;
    H[31] |= 64;
    vlong_DecLSB((vlong_t *)&k, H, 32);
    printl((vlong_t *)&k), putchar('\n');

    scanhex(H, 32,
            "e6db6867583030db3594c1a424b15f7c"
            "726624ec26b3353b10a903a6d0ab1c4c");
    vlong_DecLSB((vlong_t *)&Q, H, 32);
    printl((vlong_t *)&Q), putchar('\n');

    ecMt_point_scale(
        (vlong_t *)&k, (vlong_t *)&Q,
        (486662 - 2) / 4, 255,
        (ecMt_opctx_t *)&opctx, modp25519);
    vlong_EncLSB((vlong_t *)&Q, H, 32);
    dumphex(H, 32);
    
    return 0;
}
