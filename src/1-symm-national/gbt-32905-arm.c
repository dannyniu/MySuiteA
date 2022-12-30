/* DannyNiu/NJF, 2022-10-04. Public Domain. */

#include "gbt-32905.h"
#include <arm_neon.h>

static inline uint32_t T(int j);

#define CF1Rnd(mod4) do {                                               \
        j = i * 4 + mod4;                                               \
        *buf = T(j);                                                    \
        if( j % 32 ) *buf = (*buf << j) | (*buf >> (32 - j % 32));      \
        t = vsm3ss1q_u32(abcd, efgh, vdupq_n_u32(*buf));                \
                                                                        \
        abcd = i < 4 ?                                                  \
            vsm3tt1aq_u32(abcd, t, W[i & 3] ^ W[(i + 1) & 3], mod4) :   \
            vsm3tt1bq_u32(abcd, t, W[i & 3] ^ W[(i + 1) & 3], mod4) ;   \
                                                                        \
        efgh = i < 4 ?                                                  \
            vsm3tt2aq_u32(efgh, t, W[i & 3], mod4) :                    \
            vsm3tt2bq_u32(efgh, t, W[i & 3], mod4) ;                    \
    } while( false );

void compressfunc_sm3_ni(uint32_t V[8], uint32_t const *restrict M)
{
    uint32_t buf[4];
    uint32x4_t abcd, efgh; // a and e are at high bit positions.
    
    uint32x4_t t;
    
    uint32x4_t W[4];
    uint64x2_t *Q;

    static const uint8_t tbli1[16] = {
        12, 13, 14, 15,
        16, 17, 18, 19,
        20, 21, 22, 23,
        24, 25, 26, 27,
    };
    static const uint8_t tbli2[16] = {
        8, 9, 10, 11,
        12, 13, 14, 15,
        16, 17, 18, 19,
        20, 21, 22, 23,
    };
    
    int i, j;

    abcd = vld1q_u32(V + 0);
    efgh = vld1q_u32(V + 4);

    Q = &abcd;
    *Q = vtrn1q_u64(vtrn2q_u64(*Q, *Q), *Q);

    Q = &efgh;
    *Q = vtrn1q_u64(vtrn2q_u64(*Q, *Q), *Q);
    
    abcd = vtrn1q_u32(vtrn2q_u32(abcd, abcd), abcd);
    efgh = vtrn1q_u32(vtrn2q_u32(efgh, efgh), efgh);

    for(i=0; i<4; i++)
    {
        W[i] = vld1q_u32(M+i*4);
#if !__ARM_BIG_ENDIAN
        W[i] = vreinterpretq_u32_u8(
            vrev32q_u8(
                vreinterpretq_u8_u32(W[i])
                ));
#endif /* !__ARM_BIG_ENDIAN */
    }

    for(i=0; i<16; i++)
    {
        CF1Rnd(0);
        CF1Rnd(1);
        CF1Rnd(2);
        CF1Rnd(3);

        t = vsm3partw1q_u32(
            W[i & 3], vreinterpretq_u32_u8(
                vqtbl2q_u8(
                    (uint8x16x2_t){
                        vreinterpretq_u8_u32(W[(i + 1) & 3]),
                        vreinterpretq_u8_u32(W[(i + 2) & 3])},
                    vld1q_u8(tbli1)
                    )),
            W[(i + 3) & 3]);

        W[i & 3] = vsm3partw2q_u32(
            t, vreinterpretq_u32_u8(
                vqtbl2q_u8(
                    (uint8x16x2_t){
                        vreinterpretq_u8_u32(W[(i + 2) & 3]),
                        vreinterpretq_u8_u32(W[(i + 3) & 3])},
                    vld1q_u8(tbli2) )),
            vreinterpretq_u32_u8(
                vqtbl2q_u8(
                    (uint8x16x2_t){
                        vreinterpretq_u8_u32(W[(i + 0) & 3]),
                        vreinterpretq_u8_u32(W[(i + 1) & 3])},
                    vld1q_u8(tbli1) ))
            );
    }

    vst1q_u32(buf, abcd);
    for(i=0; i<4; i++) V[i + 0] ^= buf[3 - i];

    vst1q_u32(buf, efgh);
    for(i=0; i<4; i++) V[i + 4] ^= buf[3 - i];
}

#include "gbt-32905.c"
