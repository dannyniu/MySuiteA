/* DannyNiu/NJF, 2022-05-07. Public Domain. */

#include "rsassa-pkcs1-v1_5.h" // change this later.
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

void *RSAEncryptionWithHash_Encode_Signature(
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

static void *PKCS1v1_SSA_PSS_Sign(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen, void *restrict prng);

void *RSAEncryptionWithHash_Sign(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    void *hctx = ((pkcs1_padding_oracles_t *)po)->hashctx;

    po->hfuncs_msg.initfunc(hctx);
    po->hfuncs_msg.updatefunc(hctx, msg, msglen);
    po->status = 2;

    return PKCS1v1_SSA_PSS_Sign(x, prng_gen, prng);
}

void *RSAEncryptionWithHash_IncSign_Init(
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

void *RSAEncryptionWithHash_IncSign_Final(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen,
    void *restrict prng)
{
    x->po_base.status = 2;
    return PKCS1v1_SSA_PSS_Sign(x, prng_gen, prng);
}

static void *PKCS1v1_SSA_PSS_Sign(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen, void *restrict prng)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    void *hctx = ((pkcs1_padding_oracles_t *)po)->hashctx;
    RSA_Priv_Base_Ctx_t *dx = DeltaTo(x, offset_rsa_privctx);

    const RSAEnc_HashOID *hoid;

    vlong_size_t t;
    vlong_t *vp1;

    vlong_size_t emBits = dx->modulus_bits - 1;
    vlong_size_t emLen = (emBits + 7) / 8;
    uint8_t *ptr;

    (void)prng_gen;
    (void)prng;

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
    ptr = DeltaTo(dx, offset_w2);
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

    assert( po->status == 2 );
    if( po->hfuncs_msg.xfinalfunc ) // this should never happen.
        po->hfuncs_msg.xfinalfunc(hctx);
    po->hfuncs_msg.hfinalfunc(
        hctx, ptr + emLen - hoid->Digest_Len, hoid->Digest_Len);

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
