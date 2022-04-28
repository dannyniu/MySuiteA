/* DannyNiu/NJF, 2022-04-28. Public Domain. */

#include "x448.h"
#include "../1-integers/vlong-dat.h"

#define XECDH X448
#define CRV_BITS 448
#define A24 ((156326 - 2) / 4)
#define U_P 5 // Generator of Curve448
#define SSLEN 56
#define modp modp448

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

#include "xecdh.c.h"

int X448_PKParams(int index, CryptoParam_t *out)
{
    switch( index )
    {
    case 0:
        return 0;
        break;

    case 1:
        (void)out;
        return 224;
        break;

    default:
        return 0;
    }
}

#if ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS)

IntPtr iX448_KeyCodec(int q) { return xX448_KeyCodec(q); }

IntPtr tX448(const CryptoParam_t *P, int q)
{
    (void)P;
    return xX448(q);
}

IntPtr iX448_CtCodec(int q) { return xX448_CtCodec(q); }

#endif /* ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS) */
