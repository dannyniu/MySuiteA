/* DannyNiu/NJF, 2021-02-16. Public Domain. */

#include "EGCD.h"

vlong_t *EGCD(
    vlong_t *restrict x,
    vlong_t *restrict p,
    vlong_t *restrict quo,
    vlong_t *restrict rem,
    vlong_t *restrict y1,
    vlong_t *restrict y2)
{
    vlong_t *tmp;
    vlong_t *i = p, *j = x;

    vlong_size_t t;
    int end = false;

    for(t=0; t<y2->c; t++) y2->v[t] = 0;
    for(t=0; t<y1->c; t++) y1->v[t] = 0;
    y1->v[0] = 1;

    while( !end )
    {
        vlong_divv(rem, quo, i, j);

        tmp = i;
        i = j;
        j = rem;

        vlong_mulv_masked(tmp, y1, quo, 1, NULL, NULL);
        vlong_subv(y2, y2, tmp);

        rem = tmp;
        tmp = y2;
        y2 = y1;
        y1 = tmp;

        end = true;
        for(t=j->c; t--; ) if( j->v[t] ) end = false;
    }

    for(t=1; t<i->c; t++) if( i->v[t] ) return NULL;
    if( i->v[0] != 1 ) return NULL;
    return y2;
}
