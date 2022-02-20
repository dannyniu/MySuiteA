/* DannyNiu/NJF, 2021-12-27. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "ecp-xyz.h"
#include "curves-secp.h"

#include "../0-exec/struct-delta.c.h"
#include "../1-integers/vlong-dbg.c.h"

int test1(
    ecp_xyz_t *a,
    ecp_xyz_t *c,
    ecp_opctx_t *opctx,
    ecp_curve_t const *curve)
{
    printf("ecc_asm.set_p(");
    printl(curve->p);
    printf(") or True\n");
    
    for(long n=0; n<75*75; n++)
    {
        vlong_t *x1 = DeltaTo(a, offset_x);
        vlong_t *y1 = DeltaTo(a, offset_y);
        vlong_t *z1 = DeltaTo(a, offset_z);
        vlong_t *x3 = DeltaTo(c, offset_x);
        vlong_t *y3 = DeltaTo(c, offset_y);
        vlong_t *z3 = DeltaTo(c, offset_z);
        
        randoml(x1);
        randoml(y1);
        randoml(z1);

        ecp_point_dbl_fast(c, a, opctx, curve);

        printf("ecc_asm.point_dbl_ref(");
        printl(x1); printf(", ");
        printl(y1); printf(", ");
        printl(z1); printf(") == (");
        printl(x3); printf(", ");
        printl(y3); printf(", ");
        printl(z3); printf(")\n");
    }

    return 0;
}

int main(void)
{
    ecp384_xyz_t a;
    ecp384_xyz_t c;
    ecp384_opctx_t opctx;
    ecp_curve_t const *curve;

    printf("ecc_asm.set_a(-3) or True\n");

    // NIST P-256.

    *(ecp256_xyz_t *)&a = ECP256_XYZ_INIT();
    *(ecp256_xyz_t *)&c = ECP256_XYZ_INIT();
    *(ecp256_opctx_t *)&opctx = ECP256_OPCTX_INIT;
    curve = secp256r1;
    
    test1((void *)&a, (void *)&c, (void *)&opctx, curve);

    // NIST P-384.

    *(ecp384_xyz_t *)&a = ECP384_XYZ_INIT();
    *(ecp384_xyz_t *)&c = ECP384_XYZ_INIT();
    *(ecp384_opctx_t *)&opctx = ECP384_OPCTX_INIT;
    curve = secp384r1;

    test1((void *)&a, (void *)&c, (void *)&opctx, curve);
    
    return 0;
}
