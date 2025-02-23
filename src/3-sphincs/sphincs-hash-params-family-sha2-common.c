/* DannyNiu/NJF, 2023-11-04. Public Domain. */

#include "sphincs-hash-params-family-sha2-common.h"
#include "../2-hash/sha.h"

void SPHINCS_Hash_Comp_ADRS(
    UpdateFunc_t updatefunc, void *restrict hctx,
    const uint8_t *restrict ADRS)
{
    updatefunc(hctx, ADRS + 3, 1);
    updatefunc(hctx, ADRS + 8, 8);
    updatefunc(hctx, ADRS + 19, 1);
    updatefunc(hctx, ADRS + 20, 12);
}

void SPHINCS_HashParam_PRF_SHA2(
    bufvec_t *restrict in, void *restrict out, size_t outlen)
{
    // [0]: PK.seed
    // [1]: SK.seed
    // [2]: ADRS
    sha256_t hctx;
    static const uint8_t zeros[BLOCK_BYTES(cSHA256)] = {0};

    assert( in[0].len <= BLOCK_BYTES(cSHA256) );

    SHA256_Init(&hctx);
    SHA256_Update(&hctx, in[0].dat, in[0].len);
    SHA256_Update(&hctx, zeros, sizeof(zeros) - in[0].len);
    SPHINCS_Hash_Comp_ADRS((UpdateFunc_t)SHA256_Update, &hctx, in[2].dat);
    SHA256_Update(&hctx, in[1].dat, in[1].len);
    SHA256_Final(&hctx, out, outlen);
}

void SPHINCS_HashParam_F_SHA2(
    bufvec_t *restrict in, void *restrict out, size_t outlen)
{
    // [0]: PK.seed
    // [1]: ADRS
    // [2]: M
    sha256_t hctx;
    static const uint8_t zeros[BLOCK_BYTES(cSHA256)] = {0};

    assert( in[0].len <= BLOCK_BYTES(cSHA256) );

    SHA256_Init(&hctx);
    SHA256_Update(&hctx, in[0].dat, in[0].len);
    SHA256_Update(&hctx, zeros, sizeof(zeros) - in[0].len);
    SPHINCS_Hash_Comp_ADRS((UpdateFunc_t)SHA256_Update, &hctx, in[1].dat);
    SHA256_Update(&hctx, in[2].dat, in[2].len);
    SHA256_Final(&hctx, out, outlen);
}
