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

        // If caller wishes to verify label in constant-time,
        // then they may
        // 1. call RSAES_OAEP_Dec with the ss argument set to NULL,
        // 2. call context control function to verify the label,
        // 3. call RSAES_OAEP_Dec again to retrieve the shared secret.
        if( !ss ) *sslen = po->status; else
        {
            IntPtr i;
            uint8_t *from, *to;
            from = DeltaTo(dx, offset_w1);
            from = (void *)((vlong_t *)from)->v;
            from += k - *sslen;
            to = ss;
            
            for(i=0; i<(IntPtr)*sslen && i<po->status; i++)
            {
                // if po->status is negative, this block
                // will not be executed.
                to[i] = i < (IntPtr)po->status ? from[i] : 0;
            }
        }
        
        return (void *)ret;
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
    // unsupported during decryption - it's tested
    // separately in the context control function.
    ptr += 1 + po->hlen_msg * 2;
    k   -= 1 + po->hlen_msg * 2;

    // if there is no octet with value 0x01 to
    // separate PS from M, ... output "decryption error".
    // [implementation note]: the end condition in the
    // for loop is tweaked as a trivial protection
    // against buffer overrun.
    for(t=0; t<k-1; t++) if( ptr[t] ) break;
    err |= 1 & ~(((ptr[t] ^ 0x01) - 1) >> 8);
    
    // set the value of po->status the length.
    po->status = -err;
    for(t++; t<k; t++) po->status += err ^ 1;

    k += 1 + po->hlen_msg * 2;
    goto finish;
}

static void *RSAES_OAEP_TestLabel(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    void const *label, size_t len)
{
    pkcs1_padding_oracles_base_t *po = &x->po_base;
    RSA_Priv_Base_Ctx_t *dx = DeltaTo(x, offset_rsa_privctx);
    
    vlong_size_t t;
    void *hx = DeltaAdd(po, sizeof(pkcs1_padding_oracles_base_t));

    uint8_t *ptr;

    uint8_t digest[64];
    int32_t err = 0;
    uint16_t c = 0;
    IntPtr ret;

    // assumes decryption failures result in status being exactly -1.
    err = po->status ^ (int32_t)-1;
    err = ~err;
    err &= err >> 16;
    err &= err >> 8;
    err &= err >> 4;
    err &= err >> 2;
    err &= err >> 1;
    err &= 1;

    //
    // EME-OAEP encoding.
    
    ptr = DeltaTo(dx, offset_w1);
    ptr = (void *)((vlong_t *)ptr)->v;
    
    // label.
    
    po->hfuncs_msg.initfunc(hx);
    
    if( label )
        po->hfuncs_msg.updatefunc(hx, label, len);
    
    if( po->hfuncs_msg.xfinalfunc )
        po->hfuncs_msg.xfinalfunc(hx);
    po->hfuncs_msg.hfinalfunc(hx, digest, po->hlen_msg);

    // compare label.
    
    for(t=0; t<po->hlen_msg; t++)
        c |= ptr[t + 1 + po->hlen_msg] ^ digest[t];

    c |= c >> 4;
    c |= c >> 2;
    c |= c >> 1;
    err |= c & 1;

    po->status = -err;

    ret = (IntPtr)x & ((IntPtr)0 - (err ^ 1));
    return (void *)ret;
}

void *RSAES_OAEP_Dec_Xctrl(
    PKCS1_Priv_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    (void)veclen;
    (void)flags;
    
    switch( cmd )
    {
    case RSAES_OAEP_label_test:
        return RSAES_OAEP_TestLabel(x, bufvec[0].dat, bufvec[0].len);

    default:
        return NULL;
    }
}
