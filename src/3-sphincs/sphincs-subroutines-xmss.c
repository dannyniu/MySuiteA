/* DannyNiu/NJF, 2023-11-05. Public Domain. */

#include "sphincs-subroutines.h"
#include "../0-datum/endian.h"
#include "../0-exec/struct-delta.c.h"

void xmss_auth_path_and_root_node(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen, // root node
    uint32_t idx, void *auth, size_t alen) // auth path.
{
    // [0]: SK.seed
    // i and z skipped, they're computed on-the-fly.
    // [1]: PK.seed
    // [2]: ADRS

    // DannyNiu had taken operative liberty to implement the recursion
    // as "tree loop" to lessen the likelynood of stack overflow.

    uint8_t node[32]; // 32 is the max of n of all standardized parameters.
    uint8_t *ladder = DeltaTo(x, offset_buf_n_hapos_p1_bytes);
    uint8_t *tmp = DeltaTo(x, offset_buf_n_wotslen_bytes);

    uint32_t accum = 0, i, j, t, mask;
    SPHINCS_ADRS_t ADRS = *(SPHINCS_ADRS_t const *)in[2].dat;
    bufvec_t funcparams[3];

    if( out ) assert( outlen == x->n );
    if( auth ) assert( alen == x->n * x->hapos );

    for(j=0; j<(uint32_t)1<<x->hapos; j++)
    {
        t = 0;
        mask = 1<<t;

        ADRS.type = htobe32(WOTS_HASH);
        ADRS.keypairaddr = htobe32(j);
        ADRS.t2 = ADRS.t3 = 0;
        funcparams[0] = in[0];
        funcparams[1] = in[1];
        funcparams[2].dat = &ADRS;
        funcparams[2].len = sizeof(SPHINCS_ADRS_t);
        wots_PKgen(x, funcparams, node, x->n);

        // 2023-11-06: this is an edge case found in testing.
        if( (idx&1) == 0 && j == (idx^1) && auth )
        {
            for(i=0; i<x->n; i++)
                ((uint8_t *)auth)[i + 0 * x->n] = node[i];
        }

        while( mask )
        {
            if( mask & accum )
            {
                ADRS.type = htobe32(TREE);
                ADRS.t1 = 0;
                ADRS.treeheight = htobe32(t+1);
                ADRS.treeindex = htobe32(j>>(t+1));
                funcparams[0] = in[1];
                funcparams[1].dat = &ADRS;
                funcparams[1].len = sizeof(SPHINCS_ADRS_t);

                for(i=0; i<x->n; i++)
                {
                    tmp[i] = ladder[i + t * x->n];
                    tmp[i + x->n] = node[i];
                }

                funcparams[2].dat = tmp;
                funcparams[2].len = 2 * x->n;
                x->H(funcparams, node, x->n);

                if( auth && accum >> (t+1) == ((idx >> (t+1)) ^ 1) )
                {
                    for(i=0; i<x->n; i++)
                        ((uint8_t *)auth)[i + (t+1) * x->n] = node[i];
                }

                accum ^= mask;
                mask <<= 1;
                t ++;
            }
            else
            {
                if( auth && t == 0 && j == (idx ^ 1) )
                {
                    for(i=0; i<x->n; i++)
                        ((uint8_t *)auth)[i + 0 * x->n] = node[i];
                }

                for(i=0; i<x->n; i++)
                    ladder[i + t * x->n] = node[i];

                accum ^= mask;
                mask = 0;
                break;
            }
        }
    }

    if( out )
    {
        for(i=0; i<outlen; i++)
            ((uint8_t *)out)[i] = ladder[i + x->hapos * x->n];
    }
}

void xmss_sign(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen, uint32_t idx)
{
    // [0]: M
    // [1]: SK.seed
    // [2]: PK.seed
    // [3]: ADRS

    SPHINCS_ADRS_t ADRS = *(SPHINCS_ADRS_t const *)in[3].dat;
    bufvec_t funcparams[4];

    assert( outlen == x->n * (x->wots.len + x->hapos) );

    funcparams[0] = in[0];
    funcparams[1] = in[1];
    funcparams[2] = in[2];
    funcparams[3].dat = &ADRS;
    funcparams[3].len = sizeof(SPHINCS_ADRS_t);

    xmss_auth_path_and_root_node(
        x, funcparams+1, NULL, 0, idx,
        (uint8_t *)out + x->n * x->wots.len, x->n * x->hapos);

    ADRS.type = htobe32(WOTS_HASH);
    ADRS.keypairaddr = htobe32(idx);
    ADRS.t2 = ADRS.t3 = 0;
    wots_sign(x, funcparams, out, x->n * x->wots.len);
}

void xmss_PKFromSig(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen, uint32_t idx)
{
    // [0]: SIG_XMSS
    // [1]: M
    // [2]: PK.seed
    // [3]: ADRS

    // 64 is 2 times the max of n of all standardized parameters.
    uint8_t node[64];
    uint8_t *auth = (uint8_t *)in[0].dat + x->n * x->wots.len;

    uint32_t k, i;
    SPHINCS_ADRS_t ADRS = *(SPHINCS_ADRS_t const *)in[3].dat;
    bufvec_t funcparams[4];

    assert( outlen == x->n );

    ADRS.type = htobe32(WOTS_HASH);
    ADRS.keypairaddr = htobe32(idx);
    ADRS.t2 = ADRS.t3 = 0;

    funcparams[0].dat = in[0].dat;
    funcparams[0].len = x->n * x->wots.len;
    funcparams[1] = in[1];
    funcparams[2] = in[2];
    funcparams[3].dat = &ADRS;
    funcparams[3].len = sizeof(SPHINCS_ADRS_t);

    wots_PKFromSig(x, funcparams, node, x->n);

    ADRS.type = htobe32(TREE);
    ADRS.t1 = 0;
    ADRS.treeindex = htobe32(idx);
    for(k=0; k<x->hapos; k++)
    {
        ADRS.treeheight = htobe32(k+1);

        if( ((idx >> k) & 1) == 0 ) // even
        {
            ADRS.treeindex = htobe32(be32toh(ADRS.treeindex) / 2);
            for(i=0; i<x->n; i++)
                node[i + x->n] = auth[i + k * x->n];
        }
        else
        {
            ADRS.treeindex = htobe32((be32toh(ADRS.treeindex) - 1) / 2);
            for(i=0; i<x->n; i++)
                node[i + x->n] = node[i], node[i] = auth[i + k * x->n];
        }

        funcparams[0] = in[2];
        funcparams[1].dat = &ADRS;
        funcparams[1].len = sizeof(SPHINCS_ADRS_t);
        funcparams[2].dat = node;
        funcparams[2].len = x->n * 2;
        x->H(funcparams, node, x->n);
    }

    for(i=0; i<outlen; i++) ((uint8_t *)out)[i] = node[i];
}
