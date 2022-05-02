/* DannyNiu/NJF, 2022-05-02. Public Domain. */

#include "curves-Mt.h"
#include "../1-integers/vlong-dat.h"

extern const ecp_imod_aux_t modp448_aux;
#define SSLEN 56
#define CRV_BITS 448
#define A24 ((156326 - 2) / 4)

static void xecdh_gen_scl(
    vlong_t *restrict k,
    vlong_t *restrict K,
    ecMt_opctx_t *restrict opctx,
    ecp_imod_aux_t const *restrict imod_aux,
    GenFunc_t prng_gen, void *restrict prng)
{
    uint8_t sk[SSLEN];

    prng_gen(prng, sk, SSLEN);
    sk[0] &= 252;
    sk[55] |= 128;
    vlong_DecLSB(k, sk, SSLEN);

    ecMt_point_scale(
        k, K, A24, CRV_BITS,
        opctx, imod_aux);
}

static const ecMt_curve_t crv448 = {
    .pbits      = 448,
    .a          = 156326,
    .u_p        = 5,
    .sslen      = SSLEN,
    .gen_scl    = xecdh_gen_scl,
    .modp       = &modp448_aux,
};

const ecMt_curve_t *Curve448 = &crv448;

IntPtr iX448(int q){ return xX448(q); }
