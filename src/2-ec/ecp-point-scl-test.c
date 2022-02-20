/* DannyNiu/NJF, 2021-12-27. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "ecp-xyz.h"
#include "curves-secp.h"

#include "../0-exec/struct-delta.c.h"
#include "../1-integers/vlong-dbg.c.h"

int test1(
    ecp_xyz_t *p,
    ecp_xyz_t *q,
    ecp_xyz_t *r,
    vlong_t *b,
    ecp_opctx_t *opctx,
    const ecp_curve_t *curve)
{
    printf("ecc_asm.set_a(%d) or True\n", curve->a);
    printf("ecc_asm.set_p(");
    printl(curve->p);
    printf(") or True\n");

    for(long n=0; n<15*15; n++)
    {
        vlong_t *rx = DeltaTo(r, offset_x);
        vlong_t *ry = DeltaTo(r, offset_y);
        vlong_t *rz = DeltaTo(r, offset_z);

        randoml(b);
        ecp_xyz_inf(r);
        
        ecp_point_scale_accumulate(
            r, p, q, curve->G, b,
            opctx, curve);

        printf("ecc_asm.point_scl(");
        printl(DeltaTo(curve->G, offset_x)); printf(", ");
        printl(DeltaTo(curve->G, offset_y)); printf(", ");
        printl(DeltaTo(curve->G, offset_z)); printf(", ");
        printl(b); printf(", ");
        printf("%d", curve->a); printf(", ");
        printl(curve->b); printf(") == (");

        printl(rx); printf(", ");
        printl(ry); printf(", ");
        printl(rz); printf(")\n");
    }

    return 0;
}

int main(void)
{
    ecp384_xyz_t p;
    ecp384_xyz_t q;
    ecp384_xyz_t r;
    ecp384_opctx_t opctx;
    const ecp_curve_t *curve;
    VLONG_T(14) b;

    // NIST P-256.

    *(ecp256_xyz_t *)&p = ECP256_XYZ_INIT();
    *(ecp256_xyz_t *)&q = ECP256_XYZ_INIT();
    *(ecp256_xyz_t *)&r = ECP256_XYZ_INIT();
    *(ecp256_opctx_t *)&opctx = ECP256_OPCTX_INIT;
    curve = secp256r1;
    b.c = 10;

    test1((void *)&p, (void *)&q, (void *)&r,
          (void *)&b, (void *)&opctx, curve);

    // NIST P-384.

    *(ecp384_xyz_t *)&p = ECP384_XYZ_INIT();
    *(ecp384_xyz_t *)&q = ECP384_XYZ_INIT();
    *(ecp384_xyz_t *)&r = ECP384_XYZ_INIT();
    *(ecp384_opctx_t *)&opctx = ECP384_OPCTX_INIT;
    curve = secp384r1;
    b.c = 14;

    test1((void *)&p, (void *)&q, (void *)&r,
          (void *)&b, (void *)&opctx, curve);
    
    return 0;
}
