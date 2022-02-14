/* DannyNiu/NJF, 2022-02-11. Public Domain. */

#include "sec1-common.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

void SEC1_Keygen(
    SEC1_Common_Priv_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen, void *restrict prng)
{
    unsigned slen = x->curve->plen < 64 ? x->curve->plen : 64;
    uint8_t H[64];

    ecp_opctx_t *opctx = DeltaTo(x, offset_opctx);
    ecp_xyz_t
        *Tmp1 = DeltaTo(x, offset_Tmp1),
        *Tmp2 = DeltaTo(x, offset_Tmp2);

    ecp_xyz_t *Q = DeltaTo(x, offset_Q);
    vlong_t *d = DeltaTo(x, offset_d);

    do
    {
        prng_gen(prng, H, slen);
        vlong_OS2IP(d, H, slen);

        if( vlong_cmpv_shifted(d, x->curve->n, 0) != 2 )
            continue;
        
        if( vlong_cmpv_shifted(vlong_one, d, 0) == 1 )
            continue;

        ecp_xyz_inf(Q);
        ecp_point_scale_accumulate(
            Q, Tmp1, Tmp2, x->curve->G,
            d, opctx, x->curve);
        break;
    }
    while( true );

    // canonicalize.
    
    vlong_inv_mod_p_fermat(
        DeltaTo(opctx, offset_w),
        DeltaTo(Q,     offset_z),
        DeltaTo(opctx, offset_u),
        DeltaTo(opctx, offset_v),
        x->curve);

    vlong_mulv_masked(
        DeltaTo(opctx, offset_u),
        DeltaTo(Q,     offset_x),
        DeltaTo(opctx, offset_w), 1,
        (vlong_modfunc_t)
        x->curve->imod_aux->modfunc,
        x->curve->imod_aux->mod_ctx);

    vlong_mulv_masked(
        DeltaTo(opctx, offset_v),
        DeltaTo(Q,     offset_y),
        DeltaTo(opctx, offset_w), 1,
        (vlong_modfunc_t)
        x->curve->imod_aux->modfunc,
        x->curve->imod_aux->mod_ctx);

    vlong_cpy(DeltaTo(Q, offset_x), DeltaTo(opctx, offset_u));
    vlong_cpy(DeltaTo(Q, offset_y), DeltaTo(opctx, offset_v));
    vlong_cpy(DeltaTo(Q, offset_z), vlong_one);
}
