/* DannyNiu/NJF, 2023-11-11. Public Domain. */

#include "slhdsa.h"
#include "sphincs-subroutines.h"
#include "../0-exec/struct-delta.c.h"
#include "../0-datum/endian.h"

#if ! PKC_OMIT_PRIV_OPS

#if ! PKC_OMIT_KEYGEN

IntPtr SLHDSA_Keygen(
    SLHDSA_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    uint8_t *keys;
    SPHINCS_ADRS_t ADRS = {0};
    bufvec_t funcparams[3];

    if( !x ) return SLHDSA_CTX_SIZE(param[0].aux, param[1].aux);

    *x = SLHDSA_CTX_INIT(
        param[0].aux, param[1].aux,
        param[2].aux, param[3].aux,
        param[4].aux, param[5].aux,
        param[6].aux, param[7].aux);

    keys = DeltaTo(x, offset_key_elems);
    prng_gen(prng, keys, x->n*3);

    ADRS.layeraddr = htobe32(x->d - 1);
    funcparams[0].dat = keys + 0;
    funcparams[0].len = x->n;
    funcparams[1].dat = keys + x->n * 2;
    funcparams[1].len = x->n;
    funcparams[2].dat = &ADRS;
    funcparams[2].len = sizeof(SPHINCS_ADRS_t);
    xmss_auth_path_and_root_node(
        x, funcparams, keys + x->n * 3, x->n, 0, NULL, 0);

    return (IntPtr)x;
}

#endif /* ! PKC_OMIT_KEYGEN */

IntPtr SLHDSA_Encode_PrivateKey(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    uint8_t *keys;
    size_t t;

    (void)param;

    if( !enc ) return x->n * 4;
    if( enclen < x->n * 4 ) return -1;

    keys = DeltaTo(x, offset_key_elems);

    for(t=0; t < x->n * 4; t++)
    {
        ((uint8_t *)enc)[t] = keys[t];
    }

    return x->n * 4;
}

IntPtr SLHDSA_Decode_PrivateKey(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    uint8_t *keys;
    size_t t;

    if( !x ) return SLHDSA_CTX_SIZE(param[0].aux, param[1].aux);

    if( enclen < x->n * 4 ) return (IntPtr)NULL;

    *x = SLHDSA_CTX_INIT(
        param[0].aux, param[1].aux,
        param[2].aux, param[3].aux,
        param[4].aux, param[5].aux,
        param[6].aux, param[7].aux);

    keys = DeltaTo(x, offset_key_elems);

    for(t=0; t < x->n * 4; t++)
    {
        keys[t] = ((uint8_t *)enc)[t];
    }

    return SLHDSA_CTX_SIZE(param[0].aux, param[1].aux);
}

void *SLHDSA_Sign(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng)
{
    uint8_t *ptr;
    uint8_t *keys = DeltaTo(x, offset_key_elems);;

    // 64 is greater than all standardized values
    // for the parameters ''n'' and ''m''.
    uint8_t digest[64];

    SPHINCS_ADRS_t ADRS = {0};
    bufvec_t funcparams[4];
    size_t t;

    // byte lengths for digest, tree address, and leaf address.
    size_t mdlen = (x->k * x->a + 7) / 8;
    size_t talen = (x->h - x->hapos + 7) / 8;
    size_t lalen = (x->hapos + 7) / 8;

    //
    // R

    ptr = DeltaTo(x, offset_buf_n_bytes);

    if( prng_gen && prng ) // hedged randomized signing.
    {
        prng_gen(prng, ptr, x->n);
    }
    else // deterministically randomized signing.
    {
        for(t=0; t<x->n; t++)
            ptr[t] = keys[t + x->n * 2];
    }

    funcparams[0].dat = keys + x->n;
    funcparams[0].len = x->n;
    funcparams[1].dat = ptr;
    funcparams[1].len = x->n;
    funcparams[2].dat = msg;
    funcparams[2].len = msglen;

    ptr = DeltaTo(x, offset_signature);
    x->PRFmsg(funcparams, ptr, x->n);

    //
    // digest (and its parsing)

    funcparams[0].dat = ptr;
    funcparams[0].len = x->n;
    funcparams[1].dat = keys + x->n * 2;
    funcparams[1].len = x->n;
    funcparams[2].dat = keys + x->n * 3;
    funcparams[2].len = x->n;
    funcparams[3].dat = msg;
    funcparams[3].len = msglen;
    x->Hmsg(funcparams, digest, x->m);

    // point ``ptr'' to just after ''R''.
    ptr += x->n;

    //
    // ADRS

    for(t=0; t<talen; t++)
        ((uint8_t *)ADRS.treeaddr)[t + 12 - talen] =
            digest[t + mdlen];

    ((uint8_t *)ADRS.treeaddr)[12 - talen] &=
        (1 << ((x->h - x->hapos) & 7)) - 1;

    for(t=0; t<lalen; t++)
        ((uint8_t *)&ADRS.keypairaddr)[t + 4 - lalen] =
            digest[t + mdlen + talen];

    ((uint8_t *)&ADRS.keypairaddr)[4 - lalen] &=
        (1 << (x->hapos & 7)) - 1;

    ADRS.type = htobe32(FORS_TREE);

    //
    // SIG_FORS

    funcparams[0].dat = digest;
    funcparams[0].len = mdlen;
    funcparams[1].dat = keys + 0;
    funcparams[1].len = x->n;
    funcparams[2].dat = keys + x->n * 2;
    funcparams[2].len = x->n;
    funcparams[3].dat = &ADRS;
    funcparams[3].len = sizeof(SPHINCS_ADRS_t);
    fors_sign(x, funcparams, ptr, x->n * x->k * (x->a + 1));

    //
    // PK_FORS

    funcparams[1] = funcparams[0];
    funcparams[0].dat = ptr;
    funcparams[0].len = x->n * x->k * (x->a + 1);
    fors_pkFromSig(x, funcparams, digest, x->n);

    // point ``ptr'' to just after ''SIG_FORS''.
    ptr += x->n * x->k * (x->a + 1);

    //
    // SIG_HT

    funcparams[0].dat = digest;
    funcparams[0].len = x->n;
    funcparams[1].dat = keys + 0;
    funcparams[1].len = x->n;
    funcparams[2].dat = keys + x->n * 2;
    funcparams[2].len = x->n;

    ht_sign(
        x, funcparams, ptr, x->n * (x->h + x->d * x->wots.len),
        ADRS.treeaddr, be32toh(ADRS.keypairaddr));
    x->status = 1;

    return x;
}

void *SLHDSA_Encode_Signature(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen)
{
    size_t sigsz = x->n * (
        1 +
        x->k * (x->a + 1) +
        x->h + x->d * x->wots.len );
    size_t t;
    uint8_t *sig_buf = DeltaTo(x, offset_signature);

    if( !sig )
    {
        *siglen = sigsz;
        return NULL;
    }

    if( *siglen < sigsz ) return NULL;

    for(t=0; t<sigsz; t++) ((uint8_t *)sig)[t] = sig_buf[t];
    return sig;
}

#endif /* ! PKC_OMIT_PRIV_OPS */

IntPtr SLHDSA_Encode_PublicKey(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    uint8_t *keys;
    size_t t;

    (void)param;

    if( !enc ) return x->n * 2;
    if( enclen < x->n * 2 ) return -1;

    keys = DeltaTo(x, offset_key_elems);

    for(t=0; t < x->n * 2; t++)
    {
        ((uint8_t *)enc)[t] = keys[t + x->n * 2];
    }

    return x->n * 2;
}

#if ! PKC_OMIT_PUB_OPS

IntPtr SLHDSA_Decode_PublicKey(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    uint8_t *keys;
    size_t t;

    if( !x ) return SLHDSA_CTX_SIZE(param[0].aux, param[1].aux);

    if( enclen < x->n * 2 ) return (IntPtr)NULL;

    *x = SLHDSA_CTX_INIT(
        param[0].aux, param[1].aux,
        param[2].aux, param[3].aux,
        param[4].aux, param[5].aux,
        param[6].aux, param[7].aux);

    keys = DeltaTo(x, offset_key_elems);

    for(t=0; t < x->n * 2; t++)
    {
        keys[t + x->n * 2] = ((uint8_t *)enc)[t];
    }

    return SLHDSA_CTX_SIZE(param[0].aux, param[1].aux);
}

void *SLHDSA_Decode_Signature(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t siglen)
{
    size_t sigsz = x->n * (
        1 +
        x->k * (x->a + 1) +
        x->h + x->d * x->wots.len );
    size_t t;
    uint8_t *sig_buf = DeltaTo(x, offset_signature);

    if( siglen < sigsz ) return NULL;

    x->status = 0;

    for(t=0; t<sigsz; t++) sig_buf[t] = ((uint8_t *)sig)[t];
    return x;
}

void const *SLHDSA_Verify(
    SLHDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen)
{
    uint8_t *ptr;
    uint8_t *keys = DeltaTo(x, offset_key_elems);

    // 64 is greater than all standardized values
    // for the parameters ''n'' and ''m''.
    uint8_t digest[64];

    SPHINCS_ADRS_t ADRS = {0};
    bufvec_t funcparams[4];
    size_t t;

    // byte lengths for digest, tree address, and leaf address.
    size_t mdlen = (x->k * x->a + 7) / 8;
    size_t talen = (x->h - x->hapos + 7) / 8;
    size_t lalen = (x->hapos + 7) / 8;

status_return:
    if( x->status == 1 ) return msg;
    if( x->status == -1 ) return NULL;

    //
    // R

    ptr = DeltaTo(x, offset_signature);

    //
    // digest (and its parsing)

    funcparams[0].dat = ptr;
    funcparams[0].len = x->n;
    funcparams[1].dat = keys + x->n * 2;
    funcparams[1].len = x->n;
    funcparams[2].dat = keys + x->n * 3;
    funcparams[2].len = x->n;
    funcparams[3].dat = msg;
    funcparams[3].len = msglen;
    x->Hmsg(funcparams, digest, x->m);

    // point ``ptr'' to just after ''R''.
    ptr += x->n;

    //
    // ADRS

    for(t=0; t<talen; t++)
        ((uint8_t *)ADRS.treeaddr)[t + 12 - talen] =
            digest[t + mdlen];

    ((uint8_t *)ADRS.treeaddr)[12 - talen] &=
        (1 << ((x->h - x->hapos) & 7)) - 1;

    for(t=0; t<lalen; t++)
        ((uint8_t *)&ADRS.keypairaddr)[t + 4 - lalen] =
            digest[t + mdlen + talen];

    ((uint8_t *)&ADRS.keypairaddr)[4 - lalen] &=
        (1 << (x->hapos & 7)) - 1;

    ADRS.type = htobe32(FORS_TREE);

    //
    // SIG_FORS & PK_FORS

    funcparams[0].dat = ptr;
    funcparams[0].len = x->n * x->k * (x->a + 1);
    funcparams[1].dat = digest;
    funcparams[1].len = mdlen;
    funcparams[2].dat = keys + x->n * 2;
    funcparams[2].len = x->n;
    funcparams[3].dat = &ADRS;
    funcparams[3].len = sizeof(SPHINCS_ADRS_t);
    fors_pkFromSig(x, funcparams, digest, x->n);

    // point ``ptr'' to just after ''SIG_FORS''.
    ptr += x->n * x->k * (x->a + 1);

    //
    // SIG_HT

    funcparams[0].dat = digest;
    funcparams[0].len = x->n;
    funcparams[1].dat = ptr;
    funcparams[1].len = x->n * (x->h + x->d * x->wots.len);
    funcparams[2].dat = keys + x->n * 2;
    funcparams[2].len = x->n;
    funcparams[3].dat = keys + x->n * 3;
    funcparams[3].len = x->n;

    if( ht_verify(x, funcparams, ADRS.treeaddr,
                  be32toh(ADRS.keypairaddr)) )
        x->status = 1;
    else x->status = -1;

    goto status_return;
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS)

IntPtr iSLHDSA_KeyCodec(int q) { return xSLHDSA_KeyCodec(q); }

IntPtr tSLHDSA(const CryptoParam_t *P, int q)
{
    return xSLHDSA(P[0].aux, P[1].aux, q);
}

IntPtr iSLHDSA_CtCodec(int q) { return xSLHDSA_CtCodec(q); }

#endif /* ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS) */