/* DannyNiu/NJF, 2021-09-10. Public Domain. */

#include "rsaes-oaep.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

void *RSAES_OAEP_Encode_Ciphertext(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t *ctlen)
{
    RSA_Pub_Ctx_Hdr_t *ex = DeltaTo(x, offset_rsa_pubctx);
    vlong_t *vp = DeltaTo(ex, offset_w2);

    if( !ct )
    {
        *ctlen = ex->modulus_bits / 8;
        return ct;
    }

    // 2021-09-11: should change to equality test?
    if( *ctlen * 8 < ex->modulus_bits ) return NULL;

    vlong_I2OSP(vp, ct, *ctlen);
    return ct;
}

static void *RSAES_OAEP_SetLabel(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void const *label, size_t len)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    RSA_Pub_Ctx_Hdr_t *ex = DeltaTo(x, offset_rsa_pubctx);

    vlong_size_t t;
    void *hctx = DeltaAdd(po, sizeof(pkcs1_padding_oracles_base_t));

    vlong_size_t k = (ex->modulus_bits + 0) / 8; // UD if mod_bits % 7 != 0.
    uint8_t *ptr;

    //
    // po->status = 0;

    //
    // EME-OAEP encoding.

    ptr = DeltaTo(ex, offset_w2);
    ptr = (void *)((vlong_t *)ptr)->v;
    for(t=0; t<k; t++) ptr[t] = 0;

    // label.
    po->hfuncs_msg.initfunc(hctx);
    po->hfuncs_msg.updatefunc(hctx, label, len);
    if( po->hfuncs_msg.xfinalfunc )
        po->hfuncs_msg.xfinalfunc(hctx);
    po->hfuncs_msg.hfinalfunc(hctx, ptr + 1 + po->hlen_msg, po->hlen_msg);

    po->status = 2;
    return x;
}

void *RSAES_OAEP_Enc(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    RSA_Pub_Ctx_Hdr_t *ex = DeltaTo(x, offset_rsa_pubctx);

    vlong_size_t t;
    void *hctx = DeltaAdd(po, sizeof(pkcs1_padding_oracles_base_t));

    vlong_size_t k = (ex->modulus_bits + 0) / 8; // UD if mod_bits % 7 != 0.
    uint8_t *ptr;

    ptr = DeltaTo(ex, offset_w2);
    ptr = (void *)((vlong_t *)ptr)->v;

    if( po->status == 2 ) goto postlabel;
    po->status = 0;

    // length checking.
    if( *sslen > k - 2 * po->hlen_msg - 2 )
    {
        // po->status = -1;
        // make length check failures recoverable.
        return NULL;
    }

    //
    // EME-OAEP encoding.

    for(t=0; t<k; t++) ptr[t] = 0;

    // empty label.
    po->hfuncs_msg.initfunc(hctx);
    if( po->hfuncs_msg.xfinalfunc )
        po->hfuncs_msg.xfinalfunc(hctx);
    po->hfuncs_msg.hfinalfunc(hctx, ptr + 1 + po->hlen_msg, po->hlen_msg);

postlabel:
    // 0x01 byte.
    ptr[k - *sslen - 1] = 0x01;

    // shared secret.
    prng_gen(prng, ss, *sslen);
    for(t=0; t<*sslen; t++) ptr[t + k - *sslen] = ((uint8_t *)ss)[t];

    // seed.
    prng_gen(prng, ptr + 1, po->hlen_msg);

    mgf_auto(
        (void *)po,
        ptr + 1, po->hlen_msg, // seed
        ptr + po->hlen_msg + 1, // DB
        k - po->hlen_msg - 1,
        1);

    mgf_auto(
        (void *)po,
        ptr + po->hlen_msg + 1, // maskedDB
        k - po->hlen_msg - 1,
        ptr + 1, po->hlen_msg, // maskedSeed
        1);

    vlong_OS2IP(DeltaTo(ex, offset_w1), ptr, k);

    //
    // RSA encryption operation.

    rsa_enc(ex);

    po->status = 1;
    return ss;
}

void *RSAES_OAEP_Enc_Xctrl(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    (void)flags;

    switch( cmd )
    {
    case RSAES_OAEP_label_set:
        if( veclen < 1 ) return NULL;
        return RSAES_OAEP_SetLabel(x, bufvec[0].dat, bufvec[0].len);

    default:
        return NULL;
    }
}
