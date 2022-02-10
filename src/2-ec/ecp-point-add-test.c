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
    ecp_opctx_t *opctx,
    const ecp_curve_t *curve)
{
    printf("ecc_asm.set_p(");
    printl(curve->p);
    printf(") or True\n");

    for(long n=0; n<128*128; n++)
    {
        vlong_t *x1 = DeltaTo(p, offset_x);
        vlong_t *y1 = DeltaTo(p, offset_y);
        vlong_t *z1 = DeltaTo(p, offset_z);
        vlong_t *x2 = DeltaTo(q, offset_x);
        vlong_t *y2 = DeltaTo(q, offset_y);
        vlong_t *z2 = DeltaTo(q, offset_z);
        vlong_t *x3 = DeltaTo(r, offset_x);
        vlong_t *y3 = DeltaTo(r, offset_y);
        vlong_t *z3 = DeltaTo(r, offset_z);
        
        randoml(x1);
        randoml(y1);
        randoml(z1);
        randoml(x2);
        randoml(y2);
        randoml(z2);

        ecp_point_add_rcb15(r, p, q, opctx, curve);

        printf("ecc_asm.point_add_rcb15_ref(");
        printl(x1); printf(", ");
        printl(y1); printf(", ");
        printl(z1); printf(", ");
        printl(x2); printf(", ");
        printl(y2); printf(", ");
        printl(z2); printf(", ");
        printf("%d", curve->a); printf(", ");
        printl(curve->b); printf(") == (");
        printl(x3); printf(", ");
        printl(y3); printf(", ");
        printl(z3); printf(")\n");
    }

    return 0;
}

int main(void)
{
    ecp384_xyz_t p;
    ecp384_xyz_t q;
    ecp384_xyz_t r;
    ecp384_opctx_t opctx;
    ecp_curve_t const *curve;

    // NIST P-256.

    *(ecp256_xyz_t *)&p = ECP256_XYZ_INIT();
    *(ecp256_xyz_t *)&q = ECP256_XYZ_INIT();
    *(ecp256_xyz_t *)&r = ECP256_XYZ_INIT();
    *(ecp256_opctx_t *)&opctx = ECP256_OPCTX_INIT;
    curve = secp256r1;

    test1((void *)&p, (void *)&q, (void *)&r,
          (void *)&opctx, curve);

    // NIST P-384.

    *(ecp384_xyz_t *)&p = ECP384_XYZ_INIT();
    *(ecp384_xyz_t *)&q = ECP384_XYZ_INIT();
    *(ecp384_xyz_t *)&r = ECP384_XYZ_INIT();
    *(ecp384_opctx_t *)&opctx = ECP384_OPCTX_INIT;
    curve = secp384r1;

    test1((void *)&p, (void *)&q, (void *)&r,
          (void *)&opctx, curve);
    
    return 0;
}
