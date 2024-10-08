/* DannyNiu/NJF, 2021-10-08. Public Domain. */

#include "rsassa-pss.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

void *RSASSA_PSS_Encode_Signature(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen)
{
    RSA_Priv_Base_Ctx_t *dx = DeltaTo(x, offset_rsa_privctx);

    // 2021-10-10:
    // unused as signature serializer doesn't change working context status.
    // pkcs1_padding_oracles_base_t *po = &x->po_base;

    vlong_size_t emBits = dx->modulus_bits;
    vlong_size_t emLen = (emBits + 7) / 8;
    uint8_t *ptr;
    vlong_size_t t;

    if( !sig )
    {
        *siglen = emLen;
        return NULL;
    }

    if( *siglen < emLen ) return NULL;

    ptr = DeltaTo(dx, offset_w1);
    ptr = (void *)((vlong_t *)ptr)->v;
    for(t=0; t<emLen; t++) ((uint8_t *)sig)[t] = ptr[t];

    return sig;
}

static void *PKCS1v2_SSA_PSS_Sign(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen, void *restrict prng);

void *RSASSA_PSS_Sign(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    void *hctx = ((pkcs1_padding_oracles_t *)po)->hashctx;

    po->hfuncs_msg.initfunc(hctx);
    po->hfuncs_msg.updatefunc(hctx, msg, msglen);
    po->status = 2;

    return PKCS1v2_SSA_PSS_Sign(x, prng_gen, prng);
}

void *RSASSA_PSS_IncSign_Init(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    void *hctx = ((pkcs1_padding_oracles_t *)po)->hashctx;

    x->po_base.status = 0;
    po->hfuncs_msg.initfunc(hctx);
    *placeback = po->hfuncs_msg.updatefunc;
    return hctx;
}

void *RSASSA_PSS_IncSign_Final(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen,
    void *restrict prng)
{
    x->po_base.status = 2;
    return PKCS1v2_SSA_PSS_Sign(x, prng_gen, prng);
}

static void *PKCS1v2_SSA_PSS_Sign(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen, void *restrict prng)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    void *hctx = ((pkcs1_padding_oracles_t *)po)->hashctx;
    RSA_Priv_Base_Ctx_t *dx = DeltaTo(x, offset_rsa_privctx);

    vlong_size_t t;
    vlong_t *vp1; // , *vp2;

    vlong_size_t emBits = dx->modulus_bits - 1;
    vlong_size_t emLen = (emBits + 7) / 8;
    uint8_t *ptr;
    static const uint8_t nul[8] = {0};

    if( po->status )
    {
        if( po->status > 0 )
        {
            // po->status = 0; // 2024-10-07: may be set by friend caller(s).
            goto begin;
        }
    finish:
        if( po->status < 0 ) return NULL;
        else return x;
    }
begin:

    if( emLen < po->hlen_msg + po->slen + 2 )
    {
        po->status = -1;
        goto finish;
    }

    // Setup buffer for EM.
    ptr = DeltaTo(dx, offset_w2);
    ptr = (void *)((vlong_t *)ptr)->v;
    ptr[emLen - 1] = 0xbc;

    // Generate salt.
    prng_gen(prng, ptr + emLen - po->hlen_msg - po->slen - 1, po->slen);

    // Compute mHash.
    assert( po->status == 2 );
    if( po->hfuncs_msg.xfinalfunc )
        po->hfuncs_msg.xfinalfunc(hctx);
    po->hfuncs_msg.hfinalfunc(
        hctx, ptr + emLen - po->hlen_msg - 1, po->hlen_msg);

    // Compute H.
    po->hfuncs_msg.initfunc(hctx);
    po->hfuncs_msg.updatefunc(hctx, nul, 8);
    po->hfuncs_msg.updatefunc(
        hctx, ptr + emLen - po->hlen_msg - 1, po->hlen_msg);
    po->hfuncs_msg.updatefunc(
        hctx, ptr + emLen - po->hlen_msg - po->slen - 1, po->slen);
    if( po->hfuncs_msg.xfinalfunc )
        po->hfuncs_msg.xfinalfunc(hctx);
    po->hfuncs_msg.hfinalfunc(
        hctx, ptr + emLen - po->hlen_msg - 1, po->hlen_msg);

    // Setup DB.
    for(t=0; t < emLen - po->hlen_msg - po->slen - 2; t++) ptr[t] = 0;
    ptr[t] = 1;

    // maskedDB = DB \xor dbMask
    mgf_auto(
        (void *)po,
        ptr + emLen - po->hlen_msg - 1, po->hlen_msg, // H
        ptr, emLen - po->hlen_msg - 1, // maskedDB,dbMask.
        1);

    // Clear the leftmost 8*emLen-emBits bits.
    t = 8 * emLen - emBits;
    ptr[0] &= 0xFF >> t;

    // EM to Integer.
    vp1 = DeltaTo(dx, offset_w1);
    vlong_OS2IP(vp1, ptr, emLen);

    // RSA Maths.
    vp1 = rsa_fastdec((void *)dx);
    ptr = DeltaTo(dx, offset_w1);
    ptr = (void *)((vlong_t *)ptr)->v;
    vlong_I2OSP(vp1, ptr, emLen);

    // Finishing.
    po->status = 1;
    goto finish;
}

void *RSASSA_PSS_Sign_Xctrl(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    (void)bufvec;
    (void)veclen;

    switch( cmd )
    {
    case RSASSA_PSS_set_slen:
        x->po_base.slen = flags;
        return x;

    case RSASSA_PSS_get_slen:
        return (void *)(IntPtr)x->po_base.slen;

    default:
        return NULL;
    }
}
