/* DannyNiu/NJF, 2023-11-05. Public Domain. */

#include "sphincs-subroutines.h"
#include "../0-datum/endian.h"
#include "../0-exec/struct-delta.c.h"

static void wots_chain(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen)
{
    // [0]: X
    // [1]: i
    // [2]: s
    // [3]: PK.seed
    // [4]: ADRS

    long i = in[1].info, s = in[2].info;
    long j;
    void const *tmp = in[0].dat;
    size_t tlen = in[0].len;
    SPHINCS_ADRS_t ADRS = *(SPHINCS_ADRS_t const *)in[4].dat;
    bufvec_t funcparams[3];

    assert( i + s < x->wots.w );

    for(j=i; j<i+s; j++)
    {
        ADRS.hashaddr = htobe32(j);
        funcparams[0] = in[3];
        funcparams[1].dat = &ADRS;
        funcparams[1].len = sizeof(SPHINCS_ADRS_t);
        funcparams[2].dat = tmp;
        funcparams[2].len = tlen;
        x->F(funcparams, out, outlen);
        tmp = out;
        tlen = outlen;
    }

    if( !s )
    {
        for(i=0; (size_t)i<outlen; i++)
            ((uint8_t *)out)[i] = ((uint8_t const *)in[0].dat)[i];
    }
}

void wots_PKgen(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen)
{
    // [0]: SK.seed
    // [1]: PK.seed
    // [2]: ADRS

    uint32_t i;
    SPHINCS_ADRS_t ADRS = *(SPHINCS_ADRS_t const *)in[2].dat;
    SPHINCS_ADRS_t skADRS = ADRS;
    SPHINCS_ADRS_t wotspkADRS = ADRS;
    uint8_t *sk = DeltaTo(x, offset_buf_n_bytes);
    uint8_t *tmp = DeltaTo(x, offset_buf_n_wotslen_bytes);
    bufvec_t funcparams[5];

    skADRS.type = htobe32(WOTS_PRF);
    skADRS.t3 = 0; // 0 is an endianness-neutral value.

    // NIST.FIPS-205-ipd says setting type automatically clears
    // t1-t3. @dannyniu had taken operative liberty to do so lazily:
    //- skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())

    for(i=0; i<x->wots.len; i++)
    {
        skADRS.chainaddr = htobe32(i);
        funcparams[0] = in[1];
        funcparams[1] = in[0];
        funcparams[2].dat = &skADRS;
        funcparams[2].len = sizeof(SPHINCS_ADRS_t);
        x->PRF(funcparams, sk, x->n);

        ADRS.chainaddr = htobe32(i);
        funcparams[0].dat = sk;
        funcparams[0].len = x->n;
        funcparams[1].dat = NULL;
        funcparams[1].info = 0;
        funcparams[2].dat = NULL;
        funcparams[2].info = x->wots.w - 1;
        funcparams[3] = in[1];
        funcparams[4].dat = &ADRS;
        funcparams[4].len = sizeof(SPHINCS_ADRS_t);
        wots_chain(x, funcparams, tmp + i * x->n, x->n);
    }

    wotspkADRS.type = htobe32(WOTS_PK);
    wotspkADRS.t2 = wotspkADRS.t3 = 0;

    funcparams[0] = in[1];
    funcparams[1].dat = &wotspkADRS;
    funcparams[1].len = sizeof(SPHINCS_ADRS_t);
    funcparams[2].dat = tmp;
    funcparams[2].len = x->wots.len * x->n;
    x->T(funcparams, out, outlen);
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

    while( mt->filled < x->lgw )
    {
        mt->vbuf = mt->vbuf << 8 | mt->ptr[mt->t++];
        mt->filled += 8;
    }

    mt->filled -= x->lgw;
    ret = mt->vbuf >> mt->filled;
    ret &= (1 << x->lgw) - 1;
    return ret;
}

void wots_sign(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen)
{
    // [0]: M
    // [1]: SK.seed
    // [2]: PK.seed
    // [3]: ADRS

    uint32_t i;
    SPHINCS_ADRS_t ADRS = *(SPHINCS_ADRS_t const *)in[3].dat;
    SPHINCS_ADRS_t skADRS = ADRS;
    uint8_t *sk = DeltaTo(x, offset_buf_n_bytes);
    bufvec_t funcparams[5];

    msg_otf_t msg_otf;
    uint32_t csum = 0;
    int vmsg; // the element of vector 'msg', the concatenation of M and csum.

    assert( x->wots.len * x->n == outlen );

    msg_otf = (msg_otf_t){ .ptr = in[0].dat };

    for(i=0; i<x->wots.len1; i++)
    {
        vmsg = msg_otf_get1(x, &msg_otf);
        csum += x->wots.w - 1 - vmsg;
    }
    csum <<= 32 - x->wots.len2 * x->lgw;
    csum = htobe32(csum);

    skADRS.type = htobe32(WOTS_PRF);
    skADRS.t3 = 0;

    for(i=0; i<x->wots.len; i++)
    {
        skADRS.chainaddr = htobe32(i);
        funcparams[0] = in[2];
        funcparams[1] = in[1];
        funcparams[2].dat = &skADRS;
        funcparams[2].len = sizeof(SPHINCS_ADRS_t);
        x->PRF(funcparams, sk, x->n);

        if( i == 0 )
            msg_otf = (msg_otf_t){ .ptr = in[0].dat };

        if( i == x->wots.len1 )
            msg_otf = (msg_otf_t){ .ptr = (void *)&csum };

        vmsg = msg_otf_get1(x, &msg_otf);

        ADRS.chainaddr = htobe32(i);
        funcparams[0].dat = sk;
        funcparams[0].len = x->n;
        funcparams[1].dat = NULL;
        funcparams[1].info = 0;
        funcparams[2].dat = NULL;
        funcparams[2].info = vmsg;
        funcparams[3] = in[2];
        funcparams[4].dat = &ADRS;
        funcparams[4].len = sizeof(SPHINCS_ADRS_t);
        wots_chain(x, funcparams, (uint8_t *)out + i * x->n, x->n);
    }
}

void wots_PKFromSig(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen)
{
    // [0]: sig
    // [1]: M
    // [2]: PK.seed
    // [3]: ADRS

    uint32_t i;
    SPHINCS_ADRS_t ADRS = *(SPHINCS_ADRS_t const *)in[3].dat;
    SPHINCS_ADRS_t wotspkADRS = ADRS;
    uint8_t *tmp = DeltaTo(x, offset_buf_n_wotslen_bytes);

    // ``in'' shifted to match with ``wots_sign''.
    uint8_t const *sig = in[0].dat;
    bufvec_t funcparams[5];

    msg_otf_t msg_otf;
    uint32_t csum = 0;
    int vmsg; // the element of vector 'msg', the concatenation of M and csum.

    msg_otf = (msg_otf_t){ .ptr = in[1].dat };

    for(i=0; i<x->wots.len1; i++)
    {
        vmsg = msg_otf_get1(x, &msg_otf);
        csum += x->wots.w - 1 - vmsg;
    }
    csum <<= 32 - x->wots.len2 * x->lgw;
    csum = htobe32(csum);

    for(i=0; i<x->wots.len; i++)
    {
        if( i == 0 )
            msg_otf = (msg_otf_t){ .ptr = in[1].dat };

        if( i == x->wots.len1 )
            msg_otf = (msg_otf_t){ .ptr = (void *)&csum };

        vmsg = msg_otf_get1(x, &msg_otf);

        ADRS.chainaddr = htobe32(i);
        funcparams[0].dat = sig + i * x->n;
        funcparams[0].len = x->n;
        funcparams[1].dat = NULL;
        funcparams[1].info = vmsg;
        funcparams[2].dat = NULL;
        funcparams[2].info = x->wots.w - 1 - vmsg;
        funcparams[3] = in[2];
        funcparams[4].dat = &ADRS;
        funcparams[4].len = sizeof(SPHINCS_ADRS_t);
        wots_chain(x, funcparams, tmp + i * x->n, x->n);
    }

    wotspkADRS.type = htobe32(WOTS_PK);
    wotspkADRS.t2 = wotspkADRS.t3 = 0;

    funcparams[0] = in[2];
    funcparams[1].dat = &wotspkADRS;
    funcparams[1].len = sizeof(SPHINCS_ADRS_t);
    funcparams[2].dat = tmp;
    funcparams[2].len = x->wots.len * x->n;
    x->T(funcparams, out, outlen);
}
