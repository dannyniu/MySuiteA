/* DannyNiu/NJF, 2021-10-08. Public Domain. */

#include "rsaes-oaep.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

void *RSASSA_PSS_Decode_Signature(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t siglen)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    RSA_Pub_Ctx_Hdr_t *ex = DeltaTo(x, offset_rsa_pubctx);
    vlong_t *vp = DeltaTo(ex, offset_w1);

    vlong_OS2IP(vp, sig, siglen);

    po->status = 0;
    return x;
}

void const *RSASSA_PSS_Verify(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    void *hashctx = ((pkcs1_padding_oracles_t *)po)->hashctx;
    RSA_Pub_Ctx_Hdr_t *ex = DeltaTo(x, offset_rsa_pubctx);

    vlong_size_t t;
    vlong_t *vp1, *vp2;

    vlong_size_t emBits = ex->modulus_bits - 1;
    vlong_size_t emLen = (emBits + 7) / 8;
    uint8_t *ptr;
    static const uint8_t nul[8] = {0};

    // int32_t err = 0; // 2021-10-10: unused variable consider removing.

    if( po->status )
    {
    finish:
        if( po->status < 0 ) return NULL;
        else return msg;
    }

    if( emLen < po->hlen_msg + po->slen + 2 )
    {
        po->status = -1;
        goto finish;
    }

    // Conversion of signature to integer is performed by
    // signature loading function, bound checking is
    // performed here.

    vp1 = DeltaTo(ex, offset_w1);
    vp2 = DeltaTo(ex, offset_n);
    t = vp1->c > vp2->c ? vp1->c : vp2->c;

    while( t-- )
    {
        uint32_t u, v;
        u = vp1->c > t ? vp1->v[t] : 0;
        v = vp2->c > t ? vp2->v[t] : 0;
        if( u > v )
        {
            po->status = -1;
            goto finish;
        }
        else if( u < v ) break;
    }

    vp1 = rsa_enc(ex);
    ptr = DeltaTo(ex, offset_w1);
    ptr = (void *)((vlong_t *)ptr)->v;
    vlong_I2OSP(vp1, ptr, emLen);

    // Verification 1: right-most octet value == 0xbc.
    if( ptr[emLen - 1] != 0xbc )
    {
        po->status = -1;
        goto finish;
    }

    // Verification 2: leftmost 8*emLen-emBits bits should be clear.
    t = 8 * emLen - emBits;
    if( ptr[0] & ~(0xFF >> t) )
    {
        po->status = -1;
        goto finish;
    }

    // DB = maskedDB \xor dbMask
    mgf_auto(
        (void *)po,
        ptr + emLen - po->hlen_msg - 1, po->hlen_msg, // H
        ptr, emLen - po->hlen_msg - 1, // maskedDB,dbMask.
        1);

    // Clear leftmost 8*emLen-emBits bits of DB.
    t = 8 * emLen - emBits;
    ptr[0] &= 0xFF >> t;

    // Check padding values (0x00...00|0x01).
    t = emLen - po->hlen_msg - po->slen - 2;
    while( t-- )
    {
        if( ptr[t] )
        {
            po->status = -1;
            goto finish;
        }
    }
    if( ptr[emLen - po->hlen_msg - po->slen - 2] != 0x01 )
    {
        po->status = -1;
        goto finish;
    }

    // Computing H' prerequisite: mHash.
    vp2 = DeltaTo(ex, offset_w3);
    po->hfuncs_msg.initfunc(hashctx);
    po->hfuncs_msg.updatefunc(hashctx, msg, msglen);
    if( po->hfuncs_msg.xfinalfunc )
        po->hfuncs_msg.xfinalfunc(hashctx);
    po->hfuncs_msg.hfinalfunc(hashctx, vp2->v, po->hlen_msg);

    // Compute H'.
    po->hfuncs_msg.initfunc(hashctx);
    po->hfuncs_msg.updatefunc(hashctx, nul, 8);
    po->hfuncs_msg.updatefunc(hashctx, vp2->v, po->hlen_msg);
    po->hfuncs_msg.updatefunc(
        hashctx,
        ptr + emLen - po->hlen_msg - po->slen - 1, po->slen);
    if( po->hfuncs_msg.xfinalfunc )
        po->hfuncs_msg.xfinalfunc(hashctx);
    po->hfuncs_msg.hfinalfunc(hashctx, vp2->v, po->hlen_msg);

    // H == H'?
    for(t=0; t<po->hlen_msg; t++)
    {
        uint8_t u = ptr[emLen - po->hlen_msg - 1 + t];
        uint8_t v = ((uint8_t const *)vp2->v)[t];
        if( u != v )
        {
            po->status = -1;
            goto finish;
        }
    }

    // Finishing.
    po->status = 1;
    goto finish;
}
