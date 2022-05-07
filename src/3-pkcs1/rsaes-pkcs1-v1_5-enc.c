/* DannyNiu/NJF, 2022-05-07. Public Domain. */

#include "rsaes-pkcs1-v1_5.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

void *RSAEncryption_Encode_Ciphertext(
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

void *RSAEncryption_Enc(
    PKCS1_Pub_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    RSA_Pub_Ctx_Hdr_t *ex = DeltaTo(x, offset_rsa_pubctx);

    vlong_size_t t;
    // unused: void *hx = DeltaAdd(po, sizeof(pkcs1_padding_oracles_base_t));

    vlong_size_t k = (ex->modulus_bits + 0) / 8; // UD if mod_bits % 7 != 0.
    uint8_t *ptr;
    uint8_t *u, *v;

    ptr = DeltaTo(ex, offset_w2);
    ptr = (void *)((vlong_t *)ptr)->v;

    po->status = 0;

    // length checking.
    if( *sslen + 11 > k )
    {
        // po->status = -1;
        // make length check failures recoverable.
        return NULL;
    }

    //
    // EME-PKCS1-v1_5 encoding.

    t = k - *sslen - 3; // len(PS).
    u = v = ptr + 2;

    ptr[0] = 0;
    ptr[1] = 2;
    ptr[t + 2] = 0;

    while( t )
    {
        prng_gen(prng, u, t);

        while( true )
        {
            if( (*u = *v++) ) u++, t--;
            if( v - ptr >= t + 2) break;
        }
    }

    // shared secret.
    prng_gen(prng, ss, *sslen);
    for(t=0; t<*sslen; t++) ptr[t + k - *sslen] = ((uint8_t *)ss)[t];

    vlong_OS2IP(DeltaTo(ex, offset_w1), ptr, k);

    //
    // RSA encryption operation.

    rsa_enc(ex);

    po->status = 1;
    return ss;
}
