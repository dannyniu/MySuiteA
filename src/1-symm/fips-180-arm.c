/* DannyNiu/NJF, 2022-09-12. Public Domain. */

#include "fips-180.h"
#include <arm_neon.h>

#ifdef TEST_WITH_MOCK
#else
#endif /* TEST_WITH_MOCK */

void compressfunc_sha1_ni(uint32_t H[5], uint32_t const *restrict M)
{
    uint32x4_t w[4];
    uint32x4_t abcd, save;
    uint32_t buf[4], e;
    int i;

    for(i=0; i<4; i++)
    {
        w[i] = vld1q_u32(M+i*4);
#if !__ARM_BIG_ENDIAN
        w[i] = vreinterpretq_u32_u8(
            vrev32q_u8(
                vreinterpretq_u8_u32(w[i])
                ));
#endif /* !__ARM_BIG_ENDIAN */
    }

    abcd = vld1q_u32(H);
    e    = H[4];

    // save = _mm_add_epi32(e, w[0]);

    for(i=0; i<20; i++)
    {
        // e = abcd;

        if( 0 <= i && i < 5 )
        {
            save = vaddq_u32(w[i%4], vdupq_n_u32(0x5a827999));
            save = vsha1cq_u32(abcd, e, save);
        }

        if( 5 <= i && i < 10 )
        {
            save = vaddq_u32(w[i%4], vdupq_n_u32(0x6ed9eba1));
            save = vsha1pq_u32(abcd, e, save);
        }

        if( 10 <= i && i < 15 )
        {
            save = vaddq_u32(w[i%4], vdupq_n_u32(0x8f1bbcdc));
            save = vsha1mq_u32(abcd, e, save);
        }

        if( 15 <= i && i < 20 )
        {
            save = vaddq_u32(w[i%4], vdupq_n_u32(0xca62c1d6));
            save = vsha1pq_u32(abcd, e, save);
        }

        e = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = save;

        w[i%4] = vsha1su0q_u32(w[i%4], w[(i+1)%4], w[(i+2)%4]);
        w[i%4] = vsha1su1q_u32(w[i%4], w[(i+3)%4]);
    }

    vst1q_u32((void *)buf, abcd);
    for(i=0; i<4; i++) H[i] += buf[i];

    H[4] += e;
}

static const uint32_t K_sha256[];
static const uint64_t K_sha512[];

void compressfunc_sha256_ni(uint32_t H[8], uint32_t const *restrict M)
{
    uint32x4_t w[4];
    uint32x4_t abcd, efgh, save, temp;
    uint32_t buf[4];
    int i;

    for(i=0; i<4; i++)
    {
        w[i] = vld1q_u32(M+i*4);
#if !__ARM_BIG_ENDIAN
        w[i] = vreinterpretq_u32_u8(
            vrev32q_u8(
                vreinterpretq_u8_u32(w[i])
                ));
#endif /* !__ARM_BIG_ENDIAN */
    }

    abcd = vld1q_u32(H+0);
    efgh = vld1q_u32(H+4);

    for(i=0; i<16; i++)
    {
        temp = vaddq_u32(w[i%4], vld1q_u32(K_sha256+i*4));
        save = vsha256hq_u32(abcd, efgh, temp);
        efgh = vsha256h2q_u32(efgh, abcd, temp);
        abcd = save;

        w[i%4] = vsha256su0q_u32(w[i%4], w[(i+1)%4]);
        w[i%4] = vsha256su1q_u32(w[i%4], w[(i+2)%4], w[(i+3)%4]);
    }

    vst1q_u32((void *)buf, abcd);
    for(i=0; i<4; i++) H[i] += buf[i];

    vst1q_u32((void *)buf, efgh);
    for(i=0; i<4; i++) H[i+4] += buf[i];
}

void compressfunc_sha512_ni(uint64_t H[8], uint64_t const *restrict M)
{
    uint64x2_t w[8];
    uint64x2_t ab, cd, ef, gh;
    uint64x2_t tmp1, tmp2, tmp3, save;
    uint64_t buf[2];
    int i;

    for(i=0; i<8; i++)
    {
        w[i] = vld1q_u64(M+i*2);
#if !__ARM_BIG_ENDIAN
        w[i] = vreinterpretq_u64_u8(
            vrev64q_u8(
                vreinterpretq_u8_u64(w[i])
                ));
#endif /* !__ARM_BIG_ENDIAN */
    }

    ab = vld1q_u64(H+0);
    cd = vld1q_u64(H+2);
    ef = vld1q_u64(H+4);
    gh = vld1q_u64(H+6);

    for(i=0; i<40; i++)
    {
        tmp1 = vaddq_u64(w[i%8], vld1q_u64(K_sha512+i*2));
        tmp1 = vaddq_u64(vextq_u64(tmp1, tmp1, 1), gh);
        tmp2 = vextq_u64(cd, ef, 1);
        tmp3 = vextq_u64(ef, gh, 1);
        save = vsha512hq_u64(tmp1, tmp3, tmp2);
        tmp1 = vsha512h2q_u64(save, cd, ab);

        gh = ef;
        ef = vaddq_u64(cd, save);
        cd = ab;
        ab = tmp1;

        tmp1 = vextq_u64(w[(i+4)%8], w[(i+5)%8], 1);
        w[i%8] = vsha512su0q_u64(w[i%8], w[(i+1)%8]);
        w[i%8] = vsha512su1q_u64(w[i%8], w[(i+7)%8], tmp1);
    }

    vst1q_u64((void *)buf, ab);
    H[0] += buf[0], H[1] += buf[1];

    vst1q_u64((void *)buf, cd);
    H[2] += buf[0], H[3] += buf[1];

    vst1q_u64((void *)buf, ef);
    H[4] += buf[0], H[5] += buf[1];

    vst1q_u64((void *)buf, gh);
    H[6] += buf[0], H[7] += buf[1];
}

#define IntrinSelf
#include "fips-180.c"
