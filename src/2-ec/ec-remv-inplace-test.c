/* DannyNiu/NJF, 2021-12-27. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "ecp-xyz.h"
#include "curves-secp.h"
#include "ecMt.h"

extern const ecp_imod_aux_t modp25519_aux;
extern const ecp_imod_aux_t modp448_aux;

void printl(const vlong_t *x)
{
    printf("0x");
    for(vlong_size_t t = x->c; t--; ) printf("%08x", x->v[t]);
}

int test1(
    vlong_t *ff,
    vlong_t const *p,
    vlong_modfunc_t modfunc,
    void const *mod_ctx)
{
    for(long n=0; n<75*75; n++)
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
    VLONG_T(20) ff = VLONG_INIT(20);

    test1((void *)&ff,
          secp256r1->imod_aux->mod_ctx,
          secp256r1->imod_aux->modfunc, NULL);

    test1((void *)&ff,
          secp384r1->imod_aux->mod_ctx,
          secp384r1->imod_aux->modfunc, NULL);

    test1((void *)&ff,
          modp25519_aux.mod_ctx,
          modp25519_aux.modfunc, NULL);

    test1((void *)&ff,
          modp448_aux.mod_ctx,
          modp448_aux.modfunc, NULL);

    return 0;
}
