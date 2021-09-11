/* DannyNiu/NJF, 2021-09-10. Public Domain. */

#include "rsaes-oaep.h"
#include "../1-integers/vlong-dat.h"

// Debug code remember to remove.
void dumphex(uint8_t const *data, size_t len);
#include <stdio.h>

void *RSAES_OAEP_Encode_Ciphertext(
    RSAES_OAEP_Enc_Context_t *restrict x,
    void *restrict ct, size_t *ctlen)
{
    uint8_t *bx = (void *)x;
    RSA_Public_Context_t *ex = (void *)(bx + x->offset_rsa_pubctx);

    uint8_t *mx = (void *)ex;
    vlong_t *vp = (void *)(mx + ex->offset_w2);
    
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

void *RSAES_OAEP_Enc(
    RSAES_OAEP_Enc_Context_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng)
{
    uint8_t *bx = (void *)x;
    pkcs1_padding_oracles_base_t *po = (void *)(bx + x->offset_padding_oracle);
    RSA_Public_Context_t *ex = (void *)(bx + x->offset_rsa_pubctx);
    
    vlong_size_t t;
    uint8_t *mx = (void *)ex;
    uint8_t *hx = (uint8_t *)po + sizeof(pkcs1_padding_oracles_base_t);

    vlong_size_t k = (ex->modulus_bits + 7) / 8; // UD if mod_bits % 7 != 0.
    uint8_t *ptr;

    if( po->status )
    {
    finish:
        if( po->status < 0 ) return NULL;
        return x;
    }

    // length checking.
    
    if( *sslen > k - 2 * po->hlen_msg - 2 )
    {
        // po->status = -1;
        // make length check failures recoverable.
        return NULL;
        goto finish;
    }

    //
    // EME-OAEP encoding.
    
    ptr = mx + ex->offset_w2;
    ptr = (void *)((vlong_t *)ptr)->v;
    for(t=0; t<k; t++) ptr[t] = 0;

    // empty label.
    po->hfuncs_msg.initfunc(hx);
    if( po->hfuncs_msg.xfinalfunc )
        po->hfuncs_msg.xfinalfunc(hx);
    po->hfuncs_msg.hfinalfunc(hx, ptr + 1 + po->hlen_msg, po->hlen_msg);

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

    vlong_OS2IP((void *)(mx + ex->offset_w1), ptr, k);

    //
    // RSA encryption operation.
    
    rsa_enc(ex);
    return ss;
}
