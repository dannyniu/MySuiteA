/* DannyNiu/NJF, 2021-02-16. Public Domain. */

#include "MillerRabin.h"
#include "../1-integers/vlong.h"

#include <stdio.h>
int MillerRabin(
    vlong_t const *restrict w,
    int iterations,
    vlong_t *restrict tmp1, // temporary variables are
    vlong_t *restrict tmp2, // allocated by the caller
    vlong_t *restrict tmp,
    GenFunc_t rng, void *restrict rng_ctx)
{
    vlong_modfunc_t modfunc = (vlong_modfunc_t)vlong_remv_inplace;
    vlong_size_t a, f, i, j, n;

    n = tmp1->c = tmp2->c = tmp->c = w->c;
    f = n * 32;

    for(a=1; a<f; a++)
    {
        if( (w->v[a / 32] >> (a % 32)) & 1 )
            break;
    }

iteration_enter:
    if( !(iterations--) ) return 1;

regen: // Generate b in ]1, w-1[.
    rng(rng_ctx, tmp1->v, n * sizeof(uint32_t));

    for(i=n; --i>0; )
    {
        if( tmp1->v[i] )
            break;
    }
    
    if( i == 0 && tmp1->v[0] <= 1 ) goto regen;
    if( i > 0 ) while( tmp1->v[i] && tmp1->v[i] >= w->v[i] ) tmp1->v[i] >>= 1;
    tmp1->v[0] |= 0xAA55;
    
    // Raise b to m mod w.
    for(i=1; i<n; i++) tmp->v[i] = 0; tmp->v[0] = 1;
    for(i=a;;)
    {
        uint32_t mask = (w->v[i / 32] >> (i % 32)) & 1;

        vlong_mulv_masked(
            tmp2,
            tmp, tmp1,
            mask, modfunc, (void *)w);

        for(j=0; j<n; j++) tmp->v[j] = tmp2->v[j];

        if( ++i >= f ) break;
        
        vlong_mulv_masked(
            tmp2,
            tmp1, tmp1,
            1, modfunc, (void *)w);

        for(j=0; j<n; j++) tmp1->v[j] = tmp2->v[j];

        continue;
    }

    // if z === +/- 1 mod w: goto iteration_enter.
    for(i=n; --i>0; )
    {
        if( tmp->v[i] )
            break;
    }
    if( i == 0 && tmp->v[0] == 1 ) goto iteration_enter;

    vlong_adds(tmp1, tmp, 1, 0);
    for(i=0; i<n; i++) if( tmp1->v[i] != w->v[i] ) break;
    if( i == n ) goto iteration_enter;

    for(j=1; j<a; j++)
    {
        vlong_mulv_masked(tmp2, tmp, tmp, 1, modfunc, (void *)w);
        for(i=0; i<n; i++) tmp->v[i] = tmp2->v[i];

        // if z === +1 mod w: return COMPOSITE.
        // if z === -1 mod w: goto iteration_enter.
        for(i=n; --i>0; )
        {
            if( tmp->v[i] )
                break;
        }
        if( i == 0 && tmp->v[0] == 1 ) return 0;

        vlong_adds(tmp1, tmp, 1, 0);
        for(i=0; i<n; i++) if( tmp1->v[i] != w->v[i] ) break;
        if( i == n ) goto iteration_enter;        
    }

    // Cannot be identified as prime.
    return 0;
}
