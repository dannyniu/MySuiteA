/* DannyNiu/NJF, 2023-11-04. Public Domain. */

#include "sphincs-hash-params-family-sha512.h"
#include "../2-hash/sha.h"
#include "../2-mac/hmac-sha.h"
#include "../0-datum/endian.h"

void SPHINCS_HashParam_Hmsg_SHA512(
    bufvec_t *restrict in, void *restrict out, size_t outlen)
{
    // [0]: R
    // [1]: PK.seed
    // [2]: PK.root
    // [3]: M
    sha512_t hctx, hmgf;
    uint32_t cnt;
    uint8_t hval[OUT_BYTES(cSHA512)];
    uint8_t *ptr = out;
    size_t t;

    SHA512_Init(&hctx);
    SHA512_Update(&hctx, in[0].dat, in[0].len);
    SHA512_Update(&hctx, in[1].dat, in[1].len);
    SHA512_Update(&hctx, in[2].dat, in[2].len);
    SHA512_Update(&hctx, in[3].dat, in[3].len);
    SHA512_Final(&hctx, hval, sizeof(hval));

    SHA512_Init(&hctx);
    SHA512_Update(&hctx, in[0].dat, in[0].len);
    SHA512_Update(&hctx, in[1].dat, in[1].len);
    SHA512_Update(&hctx, hval, sizeof(hval));

    cnt = 0;
    while( outlen )
    {
        for(t=0; t<sizeof(hctx); t++)
            ((uint8_t *)&hmgf)[t] = ((uint8_t *)&hctx)[t];

        SHA512_Update(&hmgf, &cnt, sizeof(cnt));
        SHA512_Final(&hmgf, hval, sizeof(hval));

        for(t=0; t<sizeof(hval) && outlen; t++)
            *ptr++ = hval[t], outlen--;

        cnt = htobe32(be32toh(cnt)+1);
    }
}

void SPHINCS_HashParam_PRFmsg_SHA512(
    bufvec_t *restrict in, void *restrict out, size_t outlen)
{
    // [0]: SK.prf
    // [1]: opt_rand
    // [2]: M

    hmac_sha512_t hctx;

    HMAC_SHA512_Init(&hctx, in[0].dat, in[0].len);
    HMAC_Update((hmac_t *)&hctx, in[1].dat, in[1].len);
    HMAC_Update((hmac_t *)&hctx, in[2].dat, in[2].len);
    HMAC_Final((hmac_t *)&hctx, out, outlen);
}

void SPHINCS_HashParam_H_SHA512(
    bufvec_t *restrict in, void *restrict out, size_t outlen)
{
    // [0]: PK.seed
    // [1]: ADRS
    // [2]: M
    sha512_t hctx;
    static const uint8_t zeros[BLOCK_BYTES(cSHA512)] = {0};

    assert( in[0].len <= BLOCK_BYTES(cSHA512) );

    SHA512_Init(&hctx);
    SHA512_Update(&hctx, in[0].dat, in[0].len);
    SHA512_Update(&hctx, zeros, sizeof(zeros) - in[0].len);
    SPHINCS_Hash_Comp_ADRS((UpdateFunc_t)SHA512_Update, &hctx, in[1].dat);
    SHA512_Update(&hctx, in[2].dat, in[2].len);
    SHA512_Final(&hctx, out, outlen);
}
