/* DannyNiu/NJF, 2021-01-24. Public Domain. */

#include <stdio.h>
#include <string.h>
#include "vlong.h"

static VLONG_T(4) a, base, e, mod, t1, t2;

#define vlist(vl) vl.v[3], vl.v[2], vl.v[1], vl.v[0]

int main(void)
{
    a.c = base.c = e.c = mod.c = t1.c = t2.c = 4;
    
    for(long n=0; n<50*50; n++)
    {
        memset(base.v, 0, 16);
        memset(e.v,    0, 16);
        memset(mod.v,  0, 16);
        fread(base.v, 1, 12, stdin);
        fread(e.v,    1, 12, stdin);
        //e.v[0] = 0; e.v[1] = e.v[2] = e.v[3] = 0;
        fread(mod.v,  1, 12, stdin);
        if( mod.v[0] == 0 &&
            mod.v[1] == 0 &&
            mod.v[2] == 0 )
            continue;

        vlong_modexpv(
            (vlong_t *)&a,
            (vlong_t *)&base, (vlong_t *)&e,
            (vlong_t *)&t1, (vlong_t *)&t2,
            (vlong_modfunc_t)vlong_remv_inplace, (vlong_t *)&mod);

        printf(
            "pow("
            "0x%08x%08x%08x%08x, "
            "0x%08x%08x%08x%08x, "
            "0x%08x%08x%08x%08x) == "
            "0x%08x%08x%08x%08x\n",
            vlist(base), vlist(e), vlist(mod), vlist(a));
    }

    return 0;
}
