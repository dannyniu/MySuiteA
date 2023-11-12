/* DannyNiu/NJF, 2023-11-06. Public Domain. */

#include "sphincs-subroutines.h"
#include "../0-datum/endian.h"
#include "../0-exec/struct-delta.c.h"

void ht_sign(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen,
    uint32_t idx_tree_arg[3], // in big-endian
    uint32_t idx_leaf) // in host-endian
{
    // [0]: M
    // [1]: SK.seed
    // [2]: PK.seed

    uint8_t root[32]; // 32 is the max of n of all standardized parameters.
    uint32_t idx_tree[3];
    uint32_t i, j;
    SPHINCS_ADRS_t ADRS = {0};
    bufvec_t funcparams[4];
    size_t XMSS_SigLen = x->n * (x->hapos + x->wots.len);

    assert( outlen == x->d * XMSS_SigLen );

    for(i=0; i<3; i++)
    {
        ADRS.treeaddr[i] = idx_tree_arg[i];
        idx_tree[i] = be32toh(idx_tree_arg[i]);
    }

    funcparams[0] = in[0];
    funcparams[1] = in[1];
    funcparams[2] = in[2];
    funcparams[3].dat = &ADRS;
    funcparams[3].len = sizeof(SPHINCS_ADRS_t);

    xmss_sign(x, funcparams, (uint8_t *)out, XMSS_SigLen, idx_leaf);

    funcparams[1] = funcparams[0];
    funcparams[0].dat = out;
    funcparams[0].len = XMSS_SigLen;

    xmss_PKFromSig(x, funcparams, root, x->n, idx_leaf);

    for(j=1; j<x->d; j++)
    {
        idx_leaf = idx_tree[2] & (((uint32_t)1 << x->hapos) - 1);
        idx_tree[2] = idx_tree[2] >> x->hapos | idx_tree[1] << (32-x->hapos);
        idx_tree[1] = idx_tree[1] >> x->hapos | idx_tree[0] << (32-x->hapos);
        idx_tree[0] = idx_tree[0] >> x->hapos;

        ADRS.layeraddr = htobe32(j);
        for(i=0; i<3; i++) ADRS.treeaddr[i] = htobe32(idx_tree[i]);

        funcparams[0].dat = root;
        funcparams[0].len = x->n;
        funcparams[1] = in[1];

        xmss_sign(
            x, funcparams, (uint8_t *)out + j * XMSS_SigLen,
            XMSS_SigLen, idx_leaf);

        if( j < x->d - 1 ||true)
        {
            funcparams[1] = funcparams[0];
            funcparams[0].dat = (uint8_t *)out + j * XMSS_SigLen;
            funcparams[0].len = XMSS_SigLen;

            xmss_PKFromSig(x, funcparams, root, x->n, idx_leaf);
        }
    }
}

bool ht_verify(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    uint32_t idx_tree_arg[3], // in big-endian
    uint32_t idx_leaf) // in host-endian
{
    // [0]: M    // [1]: SIG_HT
    // [2]: PK.seed
    // [3]: PK.root

    uint8_t node[32]; // 32 is the max of n of all standardized parameters.
    uint32_t idx_tree[3];
    uint32_t i, j;
    SPHINCS_ADRS_t ADRS = {0};
    bufvec_t funcparams[4];
    size_t XMSS_SigLen = x->n * (x->hapos + x->wots.len);

    for(i=0; i<3; i++)
    {
        ADRS.treeaddr[i] = idx_tree_arg[i];
        idx_tree[i] = be32toh(idx_tree_arg[i]);
    }

    funcparams[0].dat = (uint8_t *)in[1].dat;
    funcparams[0].len = XMSS_SigLen;
    funcparams[1] = in[0];
    funcparams[2] = in[2];
    funcparams[3].dat = &ADRS;
    funcparams[3].len = sizeof(SPHINCS_ADRS_t);

    xmss_PKFromSig(x, funcparams, node, x->n, idx_leaf);

    for(j=1; j<x->d; j++)
    {
        idx_leaf = idx_tree[2] & (((uint32_t)1 << x->hapos) - 1);
        idx_tree[2] = idx_tree[2] >> x->hapos | idx_tree[1] << (32-x->hapos);
        idx_tree[1] = idx_tree[1] >> x->hapos | idx_tree[0] << (32-x->hapos);
        idx_tree[0] = idx_tree[0] >> x->hapos;

        ADRS.layeraddr = htobe32(j);
        for(i=0; i<3; i++) ADRS.treeaddr[i] = htobe32(idx_tree[i]);

        funcparams[0].dat = (uint8_t *)in[1].dat + j * XMSS_SigLen;
        funcparams[0].len = XMSS_SigLen;
        funcparams[1].dat = node;
        funcparams[1].len = x->n;

        xmss_PKFromSig(x, funcparams, node, x->n, idx_leaf);
    }

    for(i=0; i<x->n; i++)
        if( node[i] != ((uint8_t *)in[3].dat)[i] )
            return false;

    return true;
}
