/* DannyNiu/NJF, 2023-11-07. Public Domain. */

#include "sphincs-subroutines.h"
#include "../0-datum/endian.h"
#include "../0-exec/struct-delta.c.h"

static void fors_SKgen(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen, uint32_t idx)
{
    // [0]: SK.seed
    // [1]: PK.seed
    // [2]: ADRS

    SPHINCS_ADRS_t skADRS = *(SPHINCS_ADRS_t const *)in[2].dat;
    bufvec_t funcparams[3];

    skADRS.type = htobe32(FORS_PRF);
    skADRS.treeindex = htobe32(idx);
    skADRS.t2 = 0;

    funcparams[0] = in[1];
    funcparams[1] = in[0];
    funcparams[2].dat = &skADRS;
    funcparams[2].len = sizeof(SPHINCS_ADRS_t);

    x->PRF(funcparams, out, outlen);
}

static void fors_auth_path_and_root_node(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen, uint32_t ti,  // root nodes and their index
    uint32_t idx, void *auth, size_t alen) // auth path.
{
    // [0]: SK.seed
    // i and z skipped, they're computed on-the-fly.
    // [1]: PK.seed
    // [2]: ADRS

    // DannyNiu had taken operative liberty to implement the recursion
    // as "tree loop" to lessen the likelynood of stack overflow.

    uint8_t node[32]; // 32 is the max of n of all standardized parameters.
    uint8_t *ladder = DeltaTo(x, offset_buf_n_a_p1_bytes);
    uint8_t *tmp = DeltaTo(x, offset_buf_n_wotslen_bytes);

    uint32_t accum = 0, i, j, t, mask;
    SPHINCS_ADRS_t ADRS = *(SPHINCS_ADRS_t const *)in[2].dat;
    bufvec_t funcparams[3];

    if( out ) assert( outlen == x->n );
    if( auth ) assert( alen == x->n * x->a );

    for(j=0; j<(uint32_t)1<<x->a; j++)
    {
        t = 0;
        mask = 1<<t;

        funcparams[0] = in[0];
        funcparams[1] = in[1];
        funcparams[2] = in[2];
        fors_SKgen(x, funcparams, node, x->n, j + (ti << x->a));

        ADRS.treeheight = htobe32(0);
        ADRS.treeindex = htobe32(j + (ti << x->a));
        funcparams[0] = in[1];
        funcparams[1].dat = &ADRS;
        funcparams[1].len = sizeof(SPHINCS_ADRS_t);
        funcparams[2].dat = node;
        funcparams[2].len = x->n;
        x->F(funcparams, node, x->n);

        // 2023-11-07: the following note is inherited from "*-xmss.c"
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
                ADRS.treeheight = htobe32(t+1);
                ADRS.treeindex = htobe32((j + (ti << x->a))>>(t+1));
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
            ((uint8_t *)out)[i] = ladder[i + x->a * x->n];
    }
}

typedef struct {
    uint8_t const *ptr;
    size_t t;
    uint32_t vbuf;
    uint32_t filled;
} msg_otf_t; // otf means generating msg[i] on the fly.

static int msg_otf_get1(SLHDSA_Ctx_Hdr_t *restrict x, msg_otf_t *restrict mt)
{
    int ret;

    while( mt->filled < x->a )
    {
        mt->vbuf = mt->vbuf << 8 | mt->ptr[mt->t++];
        mt->filled += 8;
    }

    mt->filled -= x->a;
    ret = mt->vbuf >> mt->filled;
    ret &= (1 << x->a) - 1;
    return ret;
}

void fors_sign(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen)
{
    // [0]: md
    // [1]: SK.seed
    // [2]: PK.seed
    // [3]: ADRS

    uint32_t i;
    size_t FORS_ElemLen = x->n * (1 + x->a);
    msg_otf_t msg_otf;
    int ind_md;

    assert( outlen == x->k * FORS_ElemLen );

    msg_otf = (msg_otf_t){ .ptr = in[0].dat };

    for(i=0; i<x->k; i++)
    {
        ind_md = msg_otf_get1(x, &msg_otf);

        fors_SKgen(
            x, in+1, (uint8_t *)out + i * FORS_ElemLen,
            x->n, (i << x->a) + ind_md);

        fors_auth_path_and_root_node(
            x, in+1, NULL, 0, i, ind_md,
            (uint8_t *)out + i * FORS_ElemLen + x->n, x->n * x->a);
    }
}

void fors_pkFromSig(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen)
{
    // [0]: SIG_FORS
    // [1]: md
    // [2]: PK.seed
    // [3]: ADRS

    // 64 is 2 times the max of n of all standardized parameters.
    uint8_t node[64];
    uint8_t *root = DeltaTo(x, offset_buf_n_k_bytes);
    uint8_t const *Sig = in[0].dat;

    uint32_t i, j, t;
    SPHINCS_ADRS_t ADRS = *(SPHINCS_ADRS_t const *)in[3].dat;
    SPHINCS_ADRS_t forspkADRS = ADRS;
    bufvec_t funcparams[3];

    msg_otf_t msg_otf;
    int ind_md;

    assert( outlen == x->n );

    msg_otf = (msg_otf_t){ .ptr = in[1].dat };

    for(i=0; i<x->k; i++)
    {
        ind_md = msg_otf_get1(x, &msg_otf);
        ADRS.treeheight = htobe32(0);
        ADRS.treeindex = htobe32((i << x->a) + ind_md);
        funcparams[0] = in[2];
        funcparams[1].dat = &ADRS;
        funcparams[1].len = sizeof(SPHINCS_ADRS_t);
        funcparams[2].dat = Sig;
        funcparams[2].len = x->n;
        x->F(funcparams, node, x->n);
        Sig += x->n;

        for(j=0; j<x->a; j++)
        {
            ADRS.treeheight = htobe32(j+1);
            if( ((ind_md >> j) & 1) == 0 ) // even
            {
                ADRS.treeindex = htobe32(be32toh(ADRS.treeindex) / 2);
                for(t=0; t<x->n; t++)
                    node[t + x->n] = Sig[t];
            }
            else
            {
                ADRS.treeindex = htobe32((be32toh(ADRS.treeindex) - 1) / 2);
                for(t=0; t<x->n; t++)
                    node[t + x->n] = node[t], node[t] = Sig[t];
            }

            funcparams[0] = in[2];
            funcparams[1].dat = &ADRS;
            funcparams[1].len = sizeof(SPHINCS_ADRS_t);
            funcparams[2].dat = node;
            funcparams[2].len = x->n * 2;
            x->H(funcparams, node, x->n);
            Sig += x->n;
        }

        for(t=0; t<x->n; t++)
            root[t + i * x->n] = node[t];
    }

    forspkADRS.type = htobe32(FORS_ROOTS);
    forspkADRS.t2 = forspkADRS.t3 = 0;
    funcparams[0] = in[2];
    funcparams[1].dat = &forspkADRS;
    funcparams[1].len = sizeof(SPHINCS_ADRS_t);
    funcparams[2].dat = root;
    funcparams[2].len = x->n * x->k;
    x->T(funcparams, out, outlen);
}
