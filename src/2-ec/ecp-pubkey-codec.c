/* DannyNiu/NJF, 2022-02-23. Public Domain. */

#include "ecp-pubkey-codec.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

ecp_xyz_t *ecp_point_decode(
    ecp_xyz_t *restrict Q,
    void const *restrict enc,
    size_t enclen,
    ecp_xyz_t *restrict tinf,
    ecp_xyz_t *restrict tmp1,
    ecp_xyz_t *restrict tmp2,
    ecp_opctx_t *restrict opctx,
    ecp_curve_t const *restrict curve)
{
    uint8_t const *os = enc;
    vlong_t
        *x = DeltaTo(Q, offset_x),
        *y = DeltaTo(Q, offset_y),
        *z = DeltaTo(Q, offset_z);

    vlong_t
        *s = DeltaTo(opctx, offset_s),
        *t = DeltaTo(opctx, offset_t),
        *u = DeltaTo(opctx, offset_u),
        *v = DeltaTo(opctx, offset_v);

    vlong_size_t i;

    // copy z.
    vlong_cpy(z, vlong_one);

    // decode x.
    vlong_OS2IP(x, os+1, curve->plen);

    // calculate {u} = x^3 + ax + b for later verification.
    vlong_mulv_masked(
        v, x, x, 1,
        curve->imod_aux->modfunc,
        curve->imod_aux->mod_ctx);
    vlong_mulv_masked(
        u, x, v, 1,
        curve->imod_aux->modfunc,
        curve->imod_aux->mod_ctx);

    vlong_imuls(u, x, curve->a, true);
    ecp_imod_inplace(u, curve->imod_aux);
        
    vlong_addv(u, u, curve->b);
    curve->imod_aux->modfunc(
        u, curve->imod_aux->mod_ctx);

    // obtain y.
    if( *os == 0x04 && enclen == 1 + curve->plen * 2 )
    {
        vlong_OS2IP(y, os+1+curve->plen, curve->plen);
    }
    else if( (*os == 0x02 || *os == 0x03) && enclen == 1 + curve->plen )
    {
        vlong_sqrt_c3m4(y, u, s, t, curve->imod_aux);
        if( (*os & 1) != (y->v[0] & 1) )
        {
            vlong_subv(y, curve->p, y);
            curve->imod_aux->modfunc(y, curve->imod_aux->mod_ctx);
        }
    }
    else return NULL;

    // verify curve equation.
    vlong_mulv_masked(
        v, y, y, 1,
        curve->imod_aux->modfunc,
        curve->imod_aux->mod_ctx);

    if( vlong_cmpv_shifted(v, u, 0) != 0 )
        return NULL;

    // verify group order.
    ecp_xyz_inf(tinf);
    ecp_point_scale_accumulate(
        tinf, tmp1, tmp2, Q,
        curve->n, opctx, curve);

    z = DeltaTo(tinf, offset_z);
    
    for(i=0; i<z->c; i++)
        if( z->v[i] )
            return NULL;

    // successful completion.
    return Q;
}

void *ecp_point_encode(
    ecp_xyz_t const *restrict Q,
    void *restrict enc, size_t enclen,
    ecp_curve_t const *restrict curve)
{
    uint8_t *os = enc;
    vlong_t
        *x = DeltaTo(Q, offset_x),
        *y = DeltaTo(Q, offset_y);
    
    if( enclen == 1 + curve->plen * 2 )
    {
        *os = 4;
        vlong_I2OSP(x, os+1, curve->plen);
        vlong_I2OSP(y, os+1+curve->plen, curve->plen);
    }
    else if( enclen == 1 + curve->plen )
    {
        *os = 0x02 | (y->v[0] & 1);
        vlong_I2OSP(x, os+1, curve->plen);
    }
    else return NULL;

    return enc;
}
