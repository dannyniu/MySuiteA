/* DannyNiu/NJF, 2022-05-07. Public Domain. */

#include "rsassa-pkcs1-v1_5.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

void *RSAEncryptionWithHash_Decode_Signature(
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

void const *RSAEncryptionWithHash_Verify(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    void *hctx = ((pkcs1_padding_oracles_t *)po)->hashctx;
    RSA_Pub_Ctx_Hdr_t *ex = DeltaTo(x, offset_rsa_pubctx);

    const RSAEnc_HashOID *hoid;

    vlong_size_t t;
    vlong_t *vp1, *vp2;

    vlong_size_t emBits = ex->modulus_bits - 1;
    vlong_size_t emLen = (emBits + 7) / 8;
    uint8_t *ptr, *eem;
    uint8_t diff;

    if( po->status )
    {
    finish:
        if( po->status < 0 ) return NULL;
        else return msg;
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
    eem = ptr;

    ptr = DeltaTo(ex, offset_w2);
    ptr = (void *)((vlong_t *)ptr)->v;

    // -- begin - identical to that in *-sign.c --

    // Look up the hash function.
    hoid = HashOIDs_Table;
    while( hoid->HashInitFunc )
    {
        if( hoid->HashInitFunc == po->hfuncs_msg.initfunc )
            break;
        hoid++;
    }

    if( !hoid->HashInitFunc )
    {
        po->status = -1;
        goto finish;
    }

    if( emLen < hoid->DER_Prefix_Len + hoid->Digest_Len + 11 )
    {
        po->status = -1;
        goto finish;
    }

    // Setup buffer for EM.
    ptr = DeltaTo(ex, offset_w2);
    ptr = (void *)((vlong_t *)ptr)->v;

    // 00h + 01h + PS + 00h + T
    ptr[0] = 0;
    ptr[1] = 1;

    for(t=2; ; t++)
    {
        if( hoid->DER_Prefix_Len +
            hoid->Digest_Len +
            t + 1 >= emLen )
        {
            ptr[t] = 0;
            break;
        }

        ptr[t] = 0xff;
    }

    for(t=0; t<hoid->DER_Prefix_Len; t++)
        ptr[t + emLen - hoid->Digest_Len - hoid->DER_Prefix_Len] =
            ((uint8_t const *)hoid->DER_Prefix)[t];

    po->hfuncs_msg.initfunc(hctx);
    po->hfuncs_msg.updatefunc(hctx, msg, msglen);
    if( po->hfuncs_msg.xfinalfunc ) // this should never happen.
        po->hfuncs_msg.xfinalfunc(hctx);
    po->hfuncs_msg.hfinalfunc(
        hctx, ptr + emLen - hoid->Digest_Len, hoid->Digest_Len);

    // -- end - identical to that in *-sign.c --

    // EMSA-PKCS1-v1_5 message encoding verification.

    for(t=0,diff=0; t<emLen; t++)
    {
        diff |= ptr[t] ^ eem[t];
    }

    if( diff )
    {
        po->status = -1;
        goto finish;
    }

    // Finishing.
    po->status = 1;
    goto finish;
}
