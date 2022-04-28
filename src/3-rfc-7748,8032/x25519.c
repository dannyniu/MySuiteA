/* DannyNiu/NJF, 2022-04-27. Public Domain. */

#include "x25519.h"
#include "../1-integers/vlong-dat.h"

#define XECDH X25519
#define CRV_BITS 255
#define A24 ((486662 - 2) / 4)
#define U_P 9 // Generator of Curve25519
#define SSLEN 32
#define modp modp25519

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

#include "xecdh.c.h"

int X25519_PKParams(int index, CryptoParam_t *out)
{
    switch( index )
    {
    case 0:
        return 0;
        break;

    case 1:
        (void)out;
        return 128;
        break;

    default:
        return 0;
    }
}

#if ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS)

IntPtr iX25519_KeyCodec(int q) { return xX25519_KeyCodec(q); }

IntPtr tX25519(const CryptoParam_t *P, int q)
{
    (void)P;
    return xX25519(q);
}

IntPtr iX25519_CtCodec(int q) { return xX25519_CtCodec(q); }

#endif /* ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS) */
