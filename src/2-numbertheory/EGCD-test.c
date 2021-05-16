/* DannyNiu/NJF, 2021-01-24. Public Domain. */

#include <stdio.h>
#include <string.h>
#include "EGCD.h"

static VLONG_T(4) x, p, z, a, quo, rem, y1, y2;

#define vlist(vl) vl.v[3], vl.v[2], vl.v[1], vl.v[0]

static char buf[128];

int main(void)
{
    vlong_t *subret;
    x.c = p.c = quo.c = rem.c = y1.c = y2.c = 4;
    
    for(long n=0; n<50*50; n++)
    {
        memset(x.v, 0, 16);
        memset(p.v, 0, 16);
        fread(x.v, 1, 12, stdin);
        fread(p.v, 1, 12, stdin);
        memcpy(&z, &x, sizeof(x));
        memcpy(&a, &p, sizeof(p));

        subret = EGCD(
            (vlong_t *)&z,
            (vlong_t *)&a,
            (vlong_t *)&quo,
            (vlong_t *)&rem,
            (vlong_t *)&y1,
            (vlong_t *)&y2);

        if( subret )
            sprintf(buf, "0x%08x%08x%08x%08x", vlist((*subret)));
        else sprintf(buf, "None");

        printf(
            "egcd("
            "0x%08x%08x%08x%08x, "
            "0x%08x%08x%08x%08x) == %s\n",
            vlist(x), vlist(p), buf);
    }

    return 0;
}
