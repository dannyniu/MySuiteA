/* DannyNiu/NJF, 2022-05-02. Public Domain. */

#include "curves-Mt.h"
#include "../1-integers/vlong-dat.h"

extern const ecp_imod_aux_t modp25519_aux;
#define SSLEN 32
#define CRV_BITS 255
#define A24 ((486662 - 2) / 4)

static void xecdh_gen_scl(
    vlong_t *restrict k,
    vlong_t *restrict K,
    ecMt_opctx_t *restrict opctx,
    ecp_imod_aux_t const *restrict imod_aux,
    GenFunc_t prng_gen, void *restrict prng)
{
    uint8_t sk[SSLEN];

    prng_gen(prng, sk, SSLEN);
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    vlong_DecLSB(k, sk, SSLEN);

    ecMt_point_scale(
        k, K, A24, CRV_BITS,
        opctx, imod_aux);
}

static const ecMt_curve_t crv25519 = {
    .pbits      = 255,
    .a          = 486662,
    .u_p        = 9,
    .sslen      = SSLEN,
    .gen_scl    = xecdh_gen_scl,
    .modp       = &modp25519_aux,
};

const ecMt_curve_t *Curve25519 = &crv25519;

IntPtr iX25519(int q){ return xX25519(q); }
