/* DannyNiu/NJF, 2023-11-04. Public Domain. */

#include "sphincs-hash-params-family-sha256.h"
#include "../2-mac/hmac-sha.h"
#include "../0-datum/endian.h"

void SPHINCS_HashParam_Hmsg_SHA256(
    bufvec_t *restrict in, void *restrict out, size_t outlen)
{
    // [0]: R
    // [1]: PK.seed
    // [2]: PK.root
    // [3]: domain separation byte - 0 for pure, 1 for pre-hash
    // [4]: context string
    // [5]: M
    sha256_t hctx, hmgf;
    uint32_t cnt;
    uint8_t hval[OUT_BYTES(cSHA256)];
    uint8_t *ptr = out;
    size_t t;

    SHA256_Init(&hctx);
    SHA256_Update(&hctx, in[0].dat, in[0].len);
    SHA256_Update(&hctx, in[1].dat, in[1].len);
    SHA256_Update(&hctx, in[2].dat, in[2].len);
    SHA256_Update(&hctx, in[3].dat, in[3].len);
    SHA256_Update(&hctx, in[4].dat, in[4].len);
    SHA256_Update(&hctx, in[5].dat, in[5].len);
    SHA256_Final(&hctx, hval, sizeof(hval));

    SHA256_Init(&hctx);
    SHA256_Update(&hctx, in[0].dat, in[0].len);
    SHA256_Update(&hctx, in[1].dat, in[1].len);
    SHA256_Update(&hctx, hval, sizeof(hval));

    cnt = 0;
    while( outlen )
    {
        for(t=0; t<sizeof(hctx); t++)
            ((uint8_t *)&hmgf)[t] = ((uint8_t *)&hctx)[t];

        SHA256_Update(&hmgf, &cnt, sizeof(cnt));
        SHA256_Final(&hmgf, hval, sizeof(hval));

        for(t=0; t<sizeof(hval) && outlen; t++)
            *ptr++ = hval[t], outlen--;

        cnt = htobe32(be32toh(cnt)+1);
    }
}

void SPHINCS_HashParam_PRFmsg_SHA256(
    bufvec_t *restrict in, void *restrict out, size_t outlen)
{
    // [0]: SK.prf
    // [1]: opt_rand
    // [2]: domain separation byte - 0 for pure, 1 for pre-hash
    // [3]: context string
    // [4]: M

    hmac_sha256_t hctx;

    HMAC_SHA256_Init(&hctx, in[0].dat, in[0].len);
    HMAC_Update((hmac_t *)&hctx, in[1].dat, in[1].len);
    HMAC_Update((hmac_t *)&hctx, in[2].dat, in[2].len);
    HMAC_Update((hmac_t *)&hctx, in[3].dat, in[3].len);
    HMAC_Update((hmac_t *)&hctx, in[4].dat, in[4].len);
    HMAC_Final((hmac_t *)&hctx, out, outlen);
}
