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
    ecp_xyz_t *p,
    ecp_xyz_t *q,
    ecp_xyz_t *r,
    int32_t a,
    vlong_t *b,
    ecp_opctx_t *opctx,
    const ecp_imod_aux_t *aux)
{
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
        randoml(b);

        ecp_point_add_rcb15(r, p, q, a, b, opctx, aux);

        printf("ecc_asm.point_add_rcb15_ref(");
        printl(x1); printf(", ");
        printl(y1); printf(", ");
        printl(z1); printf(", ");
        printl(x2); printf(", ");
        printl(y2); printf(", ");
        printl(z2); printf(", ");
        printf("%ld", (long)a); printf(", ");
        printl(b); printf(") == (");
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
    
    const ecp_imod_aux_t *imod_aux;
    int32_t a;
    VLONG_T(14) b;

    // NIST P-256.

    *(ecp256_xyz_t *)&p = ECP256_XYZ_INIT;
    *(ecp256_xyz_t *)&q = ECP256_XYZ_INIT;
    *(ecp256_xyz_t *)&r = ECP256_XYZ_INIT;
    *(ecp256_opctx_t *)&opctx = ECP256_OPCTX_INIT;
    imod_aux = secp256r1_imod_aux;
    a = -3;
    b.c = 10;
    
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

    test1((void *)&p, (void *)&q, (void *)&r,
          a, (void *)&b, (void *)&opctx, imod_aux);

    // NIST P-384.

    *(ecp384_xyz_t *)&p = ECP384_XYZ_INIT;
    *(ecp384_xyz_t *)&q = ECP384_XYZ_INIT;
    *(ecp384_xyz_t *)&r = ECP384_XYZ_INIT;
    *(ecp384_opctx_t *)&opctx = ECP384_OPCTX_INIT;
    imod_aux = secp384r1_imod_aux;
    a = -3;
    b.c = 14;
    
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

    test1((void *)&p, (void *)&q, (void *)&r,
          a, (void *)&b, (void *)&opctx, imod_aux);
    
    return 0;
}
