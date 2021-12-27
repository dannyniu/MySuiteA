/* DannyNiu/NJF, 2021-12-27. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "secp-xyz.h"

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
    secp_xyz_t *a,
    secp_xyz_t *c,
    secp_opctx_t *opctx,
    sec_Fp_remv_callback_ctx_t *aux)
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

        secp_point_dbl(c, a, -3, opctx, aux);

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
    secp384_xyz_t a;
    secp384_xyz_t c;
    secp384_opctx_t opctx;
    
    sec_Fp_remv_callback_ctx_t modaux;

    printf("ecc_asm.set_a(-3) or True\n");

    // NIST P-256.

    *(secp256_xyz_t *)&a = SECP256_XYZ_INIT;
    *(secp256_xyz_t *)&c = SECP256_XYZ_INIT;
    *(secp256_opctx_t *)&opctx = SECP256_OPCTX_INIT;

    modaux = (sec_Fp_remv_callback_ctx_t){
        .modfunc = (vlong_modfunc_t)secp256r1_remv_inplace,
        .mod_ctx = ptr_Fp_secp256r1, };
    
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

    test1((void *)&a, (void *)&c, (void *)&opctx, &modaux);

    // NIST P-384.

    *(secp384_xyz_t *)&a = SECP384_XYZ_INIT;
    *(secp384_xyz_t *)&c = SECP384_XYZ_INIT;
    *(secp384_opctx_t *)&opctx = SECP384_OPCTX_INIT;

    modaux = (sec_Fp_remv_callback_ctx_t){
        .modfunc = (vlong_modfunc_t)secp384r1_remv_inplace,
        .mod_ctx = ptr_Fp_secp384r1, };
    
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

    test1((void *)&a, (void *)&c, (void *)&opctx, &modaux);
    
    return 0;
}
