/* DannyNiu/NJF, 2021-02-13. Public Domain. */

#include "rsa-codec-der.h"
#include "../0-exec/struct-delta.c.h"

IntPtr ber_tlv_encode_RSAPublicKey(BER_TLV_ENCODING_FUNC_PARAMS)
{
    IntPtr ret = 0, subret;

    uint8_t tlbuf[TAGLEN_MAX];
    uint8_t *ptr = tlbuf;
    IntPtr t;

    const RSA_Pub_Ctx_Hdr_t *ctx = any;

    //
    // RSAPublicKey ::= SEQUENCE {

    //
    // modulus INTEGER, -- n
    subret = ber_tlv_put_integer(
        DeltaTo(ctx, offset_n), DeltaAdd(enc, ret), enclen-ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // publicExponent INTEGER, -- e
    subret = ber_tlv_put_integer(
        DeltaTo(ctx, offset_e), DeltaAdd(enc, ret), enclen-ret);
    if( subret < 0 ) return -1;
    ret += subret;

    //
    // } -- End of "RSAPublicKey ::= SEQUENCE".

    ptr += ber_put_tag(ptr, BER_TLV_TAG_UNI(16), 1);
    ptr += ber_put_len(ptr, ret);
    subret = ptr - tlbuf;

    if( enc )
    {
        if( ret + subret > (IntPtr)enclen )
            return -1;

        for(t=ret+subret; t-->subret; )
            enc[t] = enc[t - subret];

        for(t=subret; t-->0; )
            enc[t] = tlbuf[t];
    }

    return ret + subret;
}
