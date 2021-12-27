/* DannyNiu/NJF, 2021-12-27. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "secp-xyz.h"

void printl(vlong_t *x)
{
    printf("0x");
    for(vlong_size_t t = x->c; t--; ) printf("%08x", x->v[t]);
}

int test1(vlong_t *ff, vlong_t *p, vlong_modfunc_t modfunc, void *mod_ctx)
{
    for(long n=0; n<128*128; n++)
    {
        memset(ff->v, 0, sizeof(*ff->v) * ff->c);
        fread(ff->v, 1, sizeof(*ff->v) * ff->c, stdin);

        printl(ff); printf(" %% ");
        printl(p); printf(" == ");

        modfunc(ff, mod_ctx);

        printl(ff); printf("\n");
    }

    return 0;
}

int main(void)
{
    VLONG_T(16) ff = VLONG_INIT(16);
    VLONG_T(16) p = VLONG_INIT(16);

    p.v[7] = -1;
    p.v[6] = 1;
    p.v[5] = 0;
    p.v[4] = 0;
    p.v[3] = 0;
    p.v[2] = -1;
    p.v[1] = -1;
    p.v[0] = -1;

    test1((void *)&ff, (void *)&p,
          (vlong_modfunc_t)secp256r1_remv_inplace, NULL);

    p.v[11] = -1;
    p.v[10] = -1;
    p.v[9] = -1;
    p.v[8] = -1;
    p.v[7] = -1;
    p.v[6] = -1;
    p.v[5] = -1;
    p.v[4] = -2;
    p.v[3] = -1;
    p.v[2] = 0;
    p.v[1] = 0;
    p.v[0] = -1;

    test1((void *)&ff, (void *)&p,
          (vlong_modfunc_t)secp384r1_remv_inplace, NULL);

    return 0;
}
