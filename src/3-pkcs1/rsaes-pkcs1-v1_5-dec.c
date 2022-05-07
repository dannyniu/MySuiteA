/* DannyNiu/NJF, 2022-05-07. Public Domain. */

#include "rsaes-pkcs1-v1_5.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"

void *RSAEncryption_Decode_Ciphertext(
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

void *RSAEncryption_Dec(
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
    IntPtr ret;

    if( po->status )
    {
    finish:

        // assumes decryption failures result in status being exactly -1.
        err = po->status ^ (int32_t)-1;
        err = ~err;
        err &= err >> 16;
        err &= err >> 8;
        err &= err >> 4;
        err &= err >> 2;
        err &= err >> 1;
        err &= 1;

        // assumer err is either 1 or 0 at this point.
        ret = (IntPtr)x & ((IntPtr)0 - (err ^ 1));

        if( !ss ) *sslen = po->status; else
        {
            IntPtr i;
            uint8_t *from, *to;
            from = DeltaTo(dx, offset_w1);
            from = (void *)((vlong_t *)from)->v;
            from += k - po->status;
            to = ss;

            // In case a negative status is assigned to *sslen,
            // casting it back to a signed integer will cause
            // the for block to not be executed.
            for(i=0; i<(IntPtr)*sslen; i++)
            {
                // if po->status is negative, the load expression
                // will not be executed, access overflow will not happen.
                to[i] = i < (IntPtr)po->status ? from[i] : 0;
            }
        }

        return (void *)ret;
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

    // Maths done.

    err |= ptr[0];
    err |= ptr[1] ^ 0x02;

    // find out len(PS).
    // [security note]: this loop is non-constant-time assuming
    // that the length of the message is public knowledge.
    for(t=2; t<k; t++)
    {
        if( 0 == ptr[t] )
            break;
    }

    // assert: len(PS) >= 8.
    err |= (t - 10) >> 31;

    // check for a 00h byte that separates PS from M.
    err |= (k - t - 1) >> 31;

    // consolidate error indication.
    err |= err >> 16;
    err |= err >> 8;
    err |= err >> 4;
    err |= err >> 2;
    err |= err >> 1;
    err &= 1;
    
    // below are from RSAES-OAEP
    
    // set the value of po->status the length.
    po->status = -err;
    po->status += (k-t-1) * (err ^ 1);

    goto finish;
}
