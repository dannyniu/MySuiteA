/* DannyNiu/NJF, 2022-10-04. Public Domain. */

#include "sm4.h"
#include <arm_neon.h>

static void NI_SM4Feistel(
    void const *in, void *out,
    void const *restrict w, int rev)
{
    uint32_t const *kschd = w;
    uint32x4_t X = vld1q_u32(in);
    uint64x2_t *Q;
    unsigned i;

#if !__ARM_BIG_ENDIAN
    X = vreinterpretq_u32_u8(
        vrev32q_u8(
            vreinterpretq_u8_u32(X)
            ));
#endif /* !__ARM_BIG_ENDIAN */

    for(i=0; i<8; i++)
    {
        uint32x4_t rk;

        if( rev )
        {
            rk = vld1q_u32(kschd + 28 - i * 4);
            Q = (uint64x2_t *)&rk;
            *Q = vtrn1q_u64(vtrn2q_u64(*Q, *Q), *Q);
            rk = vtrn1q_u32(vtrn2q_u32(rk, rk), rk);
        }
        else
        {
            rk = vld1q_u32(kschd + i * 4);
        }

        X = vsm4eq_u32(X, rk);
    }

    Q = (uint64x2_t *)&X;
    *Q = vtrn1q_u64(vtrn2q_u64(*Q, *Q), *Q);
    X  = vtrn1q_u32(vtrn2q_u32(X,  X),  X);

#if !__ARM_BIG_ENDIAN
    X = vreinterpretq_u32_u8(
        vrev32q_u8(
            vreinterpretq_u8_u32(X)
            ));
#endif /* !__ARM_BIG_ENDIAN */

    vst1q_u32(out, X);
}

void NI_SM4Encrypt(void const *in, void *out, void const *restrict w)
{
    NI_SM4Feistel(in, out, w, false);
}

void NI_SM4Decrypt(void const *in, void *out, void const *restrict w)
{
    NI_SM4Feistel(in, out, w, true);
}

static const uint32_t FK[];
static const uint32_t CK[];

void NI_SM4KeySched(void const *restrict key, void *restrict w)
{
    uint32x4_t K = vld1q_u32(key);
    uint32x4_t *rk = w;
    unsigned i;

#if !__ARM_BIG_ENDIAN
    K = vreinterpretq_u32_u8(
        vrev32q_u8(
            vreinterpretq_u8_u32(K)
            ));
#endif /* !__ARM_BIG_ENDIAN */

    K ^= vld1q_u32(FK);

    for(i=0; i<8; i++)
    {
        rk[i] = K = vsm4ekeyq_u32(K, vld1q_u32(CK + i * 4));
    }
}

#include "sm4.c"
