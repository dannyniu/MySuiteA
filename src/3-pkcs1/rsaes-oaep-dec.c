/* DannyNiu/NJF, 2021-09-10. Public Domain. */

#include "rsaes-oaep.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

void *RSAES_OAEP_Decode_Ciphertext(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t ctlen)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    RSA_Priv_Base_Ctx_t *dx = DeltaTo(x, offset_rsa_privctx);
    vlong_t *vp = DeltaTo(dx, offset_w1);

    vlong_OS2IP(vp, ct, ctlen);
    
    po->status = 0;
    return x;
}

void *RSAES_OAEP_Dec(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    RSA_Priv_Base_Ctx_t *dx = DeltaTo(x, offset_rsa_privctx);

    vlong_size_t t;
    vlong_t *vp1, *vp2;

    vlong_size_t k = (dx->modulus_bits + 0) / 8; // UD if mod_bits % 7 != 0.
    uint8_t *ptr;

    int32_t err = 0;

    if( po->status )
    {
    finish:
        if( po->status < 0 ) return NULL;

        if( !ss ) *sslen = po->status; else
        {
            size_t i;
            uint8_t *from, *to;
            from = DeltaTo(dx, offset_w1);
            from = (void *)((vlong_t *)from)->v;
            from += k - *sslen;
            to = ss;
            
            for(i=0; i<*sslen; i++)
            {
                // po->status is known to be positive at this point.
                // cast it to size_t to silence a comparison of
                // differently signed integers warning.
                to[i] = i < (size_t)po->status ? from[i] : 0;
            }
        }
        
        return x;
    }

    if( k < 2 * po->hlen_msg + 2 )
    {
        po->status = -1;
        goto finish;
    }

    // Conversion of ciphertext to integer is performed by
    // ciphertext loading function, bound checking is
    // performed here.

    vp1 = DeltaTo(dx, offset_w1);
    vp2 = DeltaTo(dx, offset_n);
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

    vp1 = rsa_fastdec((void *)dx);
    ptr = DeltaTo(dx, offset_w1);
    ptr = (void *)((vlong_t *)ptr)->v;
    vlong_I2OSP(vp1, ptr, k);

    mgf_auto(
        (void *)po,
        ptr + po->hlen_msg + 1, // maskedDB
        k - po->hlen_msg - 1,
        ptr + 1, po->hlen_msg, // maskedSeed
        1);

    mgf_auto(
        (void *)po,
        ptr + 1, po->hlen_msg, // seed
        ptr + po->hlen_msg + 1, // DB
        k - po->hlen_msg - 1,
        1);

    // if Y is nonzero, output "decryption error".
    err |= 1 & ~((*ptr - 1) >> 8);
    
    // x2 to ignore lHash as RSA encryption label is
    // unsupported in the MySuiteA implementation.
    ptr += 1 + po->hlen_msg * 2;
    k -= 1 + po->hlen_msg * 2;

    // if there is no octet with value 0x01 to
    // separate PS from M, ... output "decryption error".
    // [implementation note]: the end condition in the
    // for loop is tweaked as a trivial protection
    // against buffer overrun.
    for(t=0; t<k-1; t++) if( ptr[t] ) break;
    err |= 1 & ~(((ptr[t] ^ 0x01) - 1) >> 8);

    // copy message to reading buffer.
    po->status = -err;
    for(t++; t<k; t++)
    {
        // casting needed to avoid unsigned overflow.
        ptr[(long)t - 1 - (long)po->hlen_msg * 2] = ptr[t];
        po->status += err ^ 1;
    }

    goto finish;
}
