/* DannyNiu/NJF, 2021-12-27. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "ecp-xyz.h"
#include "secp-imod-aux.h"

#include "../0-exec/struct-delta.c.h"

void printl(vlong_t *x)
{
    printf("0x");
    for(vlong_size_t t = x->c; t--; ) printf("%08x", x->v[t]);
}

void randoml(vlong_t *ff)
{
    memset(ff->v, 0, sizeof(*ff->v) * ff->c);
    fread(ff->v, 1, sizeof(*ff->v) * (ff->c - 2), stdin);
}

int test1(
    ecp_xyz_t *a,
    ecp_xyz_t *c,
    ecp_opctx_t *opctx,
    const ecp_imod_aux_t *aux)
{
    for(long n=0; n<128*128; n++)
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

        ecp_point_dbl_fast(c, a, -3, opctx, aux);

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
    
    const ecp_imod_aux_t *imod_aux;

    printf("ecc_asm.set_a(-3) or True\n");

    // NIST P-256.

    *(ecp256_xyz_t *)&a = ECP256_XYZ_INIT;
    *(ecp256_xyz_t *)&c = ECP256_XYZ_INIT;
    *(ecp256_opctx_t *)&opctx = ECP256_OPCTX_INIT;
    imod_aux = secp256r1_imod_aux;
    
    printf("ecc_asm.set_p(");
    printf("0x");
    printf("%08x", -1);
    printf("%08x", 1);
    printf("%08x", 0);
    printf("%08x", 0);
    printf("%08x", 0);
    printf("%08x", -1);
    printf("%08x", -1);
    printf("%08x", -1);
    printf(") or True\n");

    test1((void *)&a, (void *)&c, (void *)&opctx, imod_aux);

    // NIST P-384.

    *(ecp384_xyz_t *)&a = ECP384_XYZ_INIT;
    *(ecp384_xyz_t *)&c = ECP384_XYZ_INIT;
    *(ecp384_opctx_t *)&opctx = ECP384_OPCTX_INIT;
    imod_aux = secp384r1_imod_aux;

    printf("ecc_asm.set_p(");
    printf("0x");
    printf("%08x", -1);
    printf("%08x", -1);
    printf("%08x", -1);
    printf("%08x", -1);
    printf("%08x", -1);
    printf("%08x", -1);
    printf("%08x", -1);
    printf("%08x", -2);
    printf("%08x", -1);
    printf("%08x", 0);
    printf("%08x", 0);
    printf("%08x", -1);
    printf(") or True\n");

    test1((void *)&a, (void *)&c, (void *)&opctx, imod_aux);
    
    return 0;
}
