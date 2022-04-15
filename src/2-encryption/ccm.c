/* DannyNiu/NJF, 2022-04-15. Public Domain. */

#include "ccm.h"
#include "../0-exec/struct-delta.c.h"

#define vzero(blk) (                                    \
        blk[000] = blk[001] = blk[002] = blk[003] =     \
        blk[004] = blk[005] = blk[006] = blk[007] =     \
        blk[010] = blk[011] = blk[012] = blk[013] =     \
        blk[014] = blk[015] = blk[016] = blk[017] = 0 )

void *CCM_Encrypt(ccm_t *restrict ccm,
                  size_t ivlen, void const *iv,
                  size_t alen, void const *aad,
                  size_t len, void const *in, void *out,
                  size_t tlen, void *T)
{
    size_t i, j;
    size_t q = 15 - ivlen;
    
    alignas(16) uint8_t B[16], Y[16], Ctr[16], S[16];
    const uint8_t *iptr = in; uint8_t *optr = out;

    void *kschd = DeltaTo(ccm, offset);

    if( ivlen < 7 || ivlen > 13 )
        return NULL;
    
    if( tlen<4 || tlen>16 || tlen%2==1 )
        return NULL;

    if( q * 8 < 64 && len >= (uint64_t)1 << (q * 8) )
        return NULL;

    // if( alen > UINT64_MAX ) return NULL; // an unreachable limit.

    //
    // Prempare Ctr_* the Counter Blocks.

    vzero(Ctr);
    Ctr[0] = (q - 1);
    Ctr[15] = 1;
    
    for(i=0; i<ivlen; i++)
    {
        Ctr[i+1] = ((const uint8_t *)iv)[i];
    }
    
    ccm->enc(Ctr, S, kschd);
    
    //
    // Compute B_0 and Y_0

    vzero(B);
    B[0] = (alen ? 1 : 0) << 6 | ((tlen - 2) / 2) << 3 | (q - 1);
    
    for(i=0; i<ivlen; i++)
    {
        B[i+1] = ((const uint8_t *)iv)[i];
    }

    for(i=1; i<=q; i++)
    {
        B[i+ivlen] = len >> (q - i) * 8;
    }

    ccm->enc(B, Y, kschd);

    //
    // Encode a for AAD
    
    vzero(B);

    if( alen == 0 )
    {
        j = 0;
    }
    
    else if( alen < 0xFF00 )
    {
        B[0] = alen >> 8;
        B[1] = alen;
        j = 2;
    }
    
    else if( alen <= UINT32_MAX )
    {
        B[0] = 0xFF;
        B[1] = 0xFE;
        B[2] = (uint64_t)alen >> 24;
        B[3] = (uint64_t)alen >> 16;
        B[4] = (uint64_t)alen >> 8;
        B[5] = (uint64_t)alen;
        j = 6;
    }
    
    else
    {
        B[0] = 0xFF;
        B[1] = 0xFE;
        B[2] = (uint64_t)alen >> 56;
        B[3] = (uint64_t)alen >> 48;
        B[4] = (uint64_t)alen >> 40;
        B[5] = (uint64_t)alen >> 32;
        B[6] = (uint64_t)alen >> 24;
        B[7] = (uint64_t)alen >> 16;
        B[8] = (uint64_t)alen >> 8;
        B[9] = (uint64_t)alen;
        j = 10;
    }

    //
    // Accumulate AAD for CBC-MAC.
    
    for(i=0; i<alen; )
    {
        B[j++] = ((const uint8_t *)aad)[i++];
        if( j >= 16 )
        {
            for(j=0; j<16; j++) B[j] ^= Y[j];
            ccm->enc(B, Y, kschd);
            vzero(B);
            j = 0;
        }
    }

    if( j )
    {
        for(j=0; j<16; j++) B[j] ^= Y[j];
        ccm->enc(B, Y, kschd);
        vzero(B);
        j = 0;
    }
    
    //
    // Accumulate P for CBC-MAC and CTR-Encryption.
    
    for(i=0; i<len; )
    {
        optr[i] = (B[j] = iptr[i]) ^ S[j];
        i++, j++;
        
        if( j >= 16 )
        {
            for(i=0; i<16; i++) B[i] ^= Y[i];
            ccm->enc(B, Y, kschd);

            for(j=16; --j>ivlen; )
                if( ++Ctr[j] )
                    break;
            ccm->enc(Ctr, S, kschd);
            
            vzero(B);
            j = 0;
        }
    }

    if( j )
    {
        for(i=0; i<16; i++) B[i] ^= Y[i];
        ccm->enc(B, Y, kschd);
        vzero(B);
        j = 0;
    }

    for(j=16; --j>ivlen; ) Ctr[j] = 0;
    ccm->enc(Ctr, S, kschd);
    for(j=0; j<tlen; j++) ((uint8_t *)T)[j] = Y[j] ^ S[j];

    return out;
}

void *CCM_Decrypt(ccm_t *restrict ccm,
                  size_t ivlen, void const *iv,
                  size_t alen, void const *aad,
                  size_t len, void const *in, void *out,
                  size_t tlen, void const *T)
{
    uint16_t tcmp = 0;
    
    size_t i, j;
    size_t q = 15 - ivlen;
    
    alignas(16) uint8_t B[16], Y[16], Ctr[16], S[16];
    const uint8_t *iptr = in; uint8_t *optr = out;

    void *kschd = DeltaTo(ccm, offset);

    if( ivlen < 7 || ivlen > 13 )
        return NULL;
    
    if( tlen<4 || tlen>16 || tlen%2==1 )
        return NULL;

    if( q * 8 < 64 && len >= (uint64_t)1 << (q * 8) )
        return NULL;
    
    // if( alen > UINT64_MAX ) return NULL; // an unreachable limit.

    //
    // Prempare Ctr_* the Counter Blocks and S_0.

    vzero(Ctr);
    Ctr[0] = (q - 1);
    Ctr[15] = 1;
    
    for(i=0; i<ivlen; i++)
    {
        Ctr[i+1] = ((const uint8_t *)iv)[i];
    }
    
    ccm->enc(Ctr, S, kschd);
    
    //
    // Compute B_0 and Y_0
    
    vzero(B);
    B[0] = (alen ? 1 : 0) << 6 | ((tlen - 2) / 2) << 3 | (q - 1);
    
    for(i=0; i<ivlen; i++)
    {
        B[i+1] = ((const uint8_t *)iv)[i];
    }

    for(i=1; i<=q; i++)
    {
        B[i+ivlen] = len >> (q - i) * 8;
    }
    
    ccm->enc(B, Y, kschd);

    //
    // Encode a for AAD
    
    vzero(B);

    if( alen == 0 )
    {
        j = 0;
    }
        
    else if( alen < 0xFF00 )
    {
        B[0] = alen >> 8;
        B[1] = alen;
        j = 2;
    }
    
    else if( alen <= UINT32_MAX )
    {
        B[0] = 0xFF;
        B[1] = 0xFE;
        B[2] = (uint64_t)alen >> 24;
        B[3] = (uint64_t)alen >> 16;
        B[4] = (uint64_t)alen >> 8;
        B[5] = (uint64_t)alen;
        j = 6;
    }
    
    else
    {
        B[0] = 0xFF;
        B[1] = 0xFE;
        B[2] = (uint64_t)alen >> 56;
        B[3] = (uint64_t)alen >> 48;
        B[4] = (uint64_t)alen >> 40;
        B[5] = (uint64_t)alen >> 32;
        B[6] = (uint64_t)alen >> 24;
        B[7] = (uint64_t)alen >> 16;
        B[8] = (uint64_t)alen >> 8;
        B[9] = (uint64_t)alen;
        j = 10;
    }

    //
    // Accumulate AAD for CBC-MAC.
    
    for(i=0; i<alen; )
    {
        B[j++] = ((const uint8_t *)aad)[i++];
        if( j >= 16 )
        {
            for(j=0; j<16; j++) B[j] ^= Y[j];
            ccm->enc(B, Y, kschd);
            vzero(B);
            j = 0;
        }
    }

    if( j )
    {
        for(j=0; j<16; j++) B[j] ^= Y[j];
        ccm->enc(B, Y, kschd);
        vzero(B);
        j = 0;
    }
    
    //
    // Accumulate P for CBC-MAC.
    
    for(i=0; i<len; )
    {
        B[j] = iptr[i] ^ S[j];
        i++, j++;
        
        if( j >= 16 )
        {
            for(i=0; i<16; i++) B[i] ^= Y[i];
            ccm->enc(B, Y, kschd);

            for(j=16; --j>ivlen; )
                if( ++Ctr[j] )
                    break;
            ccm->enc(Ctr, S, kschd);
            
            vzero(B);
            j = 0;
        }
    }

    if( j )
    {
        for(i=0; i<16; i++) B[i] ^= Y[i];
        ccm->enc(B, Y, kschd);
        vzero(B);
        j = 0;
    }

    for(j=16; --j>ivlen; ) Ctr[j] = 0;
    ccm->enc(Ctr, S, kschd);
    for(j=0; j<tlen; j++)
        tcmp |= ((uint8_t *)T)[j] ^ Y[j] ^ S[j];

    if( (tcmp - 1) >> 15 == 0 ) return NULL;

    //
    // CTR-Decryption.

    Ctr[15] = 1;
    for(j=15; --j>ivlen; ) Ctr[j] = 0;
    ccm->enc(Ctr, S, kschd);
    j = 0;
    
    for(i=0; i<len; )
    {
        optr[i] = iptr[i] ^ S[j];
        i++, j++;
        
        if( j >= 16 )
        {
            for(j=16; --j>ivlen; )
                if( ++Ctr[j] )
                    break;
            
            ccm->enc(Ctr, S, kschd);
            j = 0;
        }
    }

    return out;
}

#define cT(q) (P->param ? P->template(P->param, q) : P->info(q))

IntPtr tCCM(const CryptoParam_t *P, int q) { return xCCM(T,q); }

void *CCM_T_Init(
    const CryptoParam_t *restrict P,
    ccm_t *restrict x,
    void const *restrict k,
    size_t klen)
{
    if( klen != (size_t)KEY_BYTES(cT) )
        return NULL;
    *x = CCM_INIT(cT);
    KSCHD_FUNC(cT)(k, (char *)x + sizeof(*x));
    return x;
}
