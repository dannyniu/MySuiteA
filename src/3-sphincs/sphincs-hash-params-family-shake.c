/* DannyNiu/NJF, 2023-11-12. Public Domain. */

#include "sphincs-hash-params-family-shake.h"

void SPHINCS_HashParam_Hmsg_SHAKE256(
    bufvec_t *restrict in, void *restrict out, size_t outlen)
{
    // [0]: R
    // [1]: PK.seed
    // [2]: PK.root
    // [3]: domain separation byte - 0 for pure, 1 for pre-hash
    // [4]: context string
    // [5]: M

    shake_t hctx;
    int i;

    SHAKE256_Init(&hctx);
    for(i=0; i<6; i++)
        SHAKE_Write(&hctx, in[i].dat, in[i].len);

    SHAKE_Final(&hctx);
    SHAKE_Read(&hctx, out, outlen);
}

void SPHINCS_HashParam_PRF_SHAKE256(
    bufvec_t *restrict in, void *restrict out, size_t outlen)
{
    // [0]: PK.seed
    // [1]: SK.seed
    // [2]: ADRS

    shake_t hctx;

    SHAKE256_Init(&hctx);

    SHAKE_Write(&hctx, in[0].dat, in[0].len);
    SHAKE_Write(&hctx, in[2].dat, in[2].len);
    SHAKE_Write(&hctx, in[1].dat, in[1].len);
    
    SHAKE_Final(&hctx);
    SHAKE_Read(&hctx, out, outlen);
}

void SPHINCS_HashParam_PRFmsg_SHAKE256(
    bufvec_t *restrict in, void *restrict out, size_t outlen)
{
    // [0]: SK.prf
    // [1]: opt_rand
    // [2]: domain separation byte - 0 for pure, 1 for pre-hash
    // [3]: context string
    // [4]: M

    shake_t hctx;
    int i;

    SHAKE256_Init(&hctx);
    for(i=0; i<5; i++)
        SHAKE_Write(&hctx, in[i].dat, in[i].len);

    SHAKE_Final(&hctx);
    SHAKE_Read(&hctx, out, outlen);
}

void SPHINCS_HashParam_F_SHAKE256(
    bufvec_t *restrict in, void *restrict out, size_t outlen)
{
    // [0]: PK.seed
    // [1]: ADRS
    // [2]: M
    shake_t hctx;
    int i;

    SHAKE256_Init(&hctx);
    for(i=0; i<3; i++)
        SHAKE_Write(&hctx, in[i].dat, in[i].len);

    SHAKE_Final(&hctx);
    SHAKE_Read(&hctx, out, outlen);
}
