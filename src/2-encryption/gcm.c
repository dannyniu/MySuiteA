/* DannyNiu/NJF, 2018-02-11. Public Domain. */

#include "gcm.h"
#include "../1-symm/galois128.h"
#include "../0-datum/endian.h"

void GCM_Encrypt(gcm_t *restrict gcm,
                 void const *restrict iv,
                 size_t alen, const void *aad,
                 size_t len, const void *in, void *out,
                 size_t tlen, void *T)
{
    size_t i, j;
    
    alignas(16) uint32_t
        J0[4], 
        CB[4],
        S[4] = {0};
    alignas(16) uint8_t X[16];
    const uint8_t *iptr = in; uint8_t *optr = out;

    void *kschd = (uint8_t *)gcm + gcm->offset;

    // Prepare J0. 
    for(i=0; i<3; i++){ J0[i] = ((const uint32_t *)iv)[i]; } J0[3] = htobe32(1);

    // The A part of S. 
    for(j=0; j<alen; j+=16)
    {
        for(i=0; i<16; i++)
            X[i] = i+j < alen ? ((const uint8_t *)aad)[i+j] : 0;
        
        galois128_hash1block(S, gcm->H, X);
    }
    
    // GCTR: First CB. 
    for(i=0; i<4; i++){ CB[i] = J0[i]; }

    // The C part of S. 
    for(j=0; j<len; j+=16)
    {
        CB[3] = htobe32(be32toh(CB[3])+1);
        gcm->enc(CB, X, kschd);
        
        for(i=0; i<16; i++)
            X[i] = i+j < len ? (optr[i+j] = iptr[i+j]^X[i]) : 0;

        galois128_hash1block(S, gcm->H, X);
    }

    // The len(A) and len(C) part of S. 
    ((uint64_t *)X)[0] = htobe64(alen*8);
    ((uint64_t *)X)[1] = htobe64(len*8);
    galois128_hash1block(S, gcm->H, X);

    // Calculate T. Zero-extends if tlen>16. 
    gcm->enc(J0, X, kschd);
    for(i=0; i<4; i++) ((uint32_t *)X)[i] ^= S[i];
    for(i=0; i<tlen; i++) ((uint8_t *)T)[i] = i<16 ? X[i] : 0;
}

void *GCM_Decrypt(gcm_t *restrict gcm,
                  void const *restrict iv,
                  size_t alen, const void *aad,
                  size_t len, const void *in, void *out,
                  size_t tlen, const void *T)
{
    size_t i, j;
    
    alignas(16) uint32_t
        J0[4], 
        CB[4],
        S[4] = {0};
    alignas(16) uint8_t X[16];
    const uint8_t *iptr = in; uint8_t *optr = out;

    void *kschd = (uint8_t *)gcm + gcm->offset;

    // Prepare J0. 
    for(i=0; i<3; i++){ J0[i] = ((const uint32_t *)iv)[i]; } J0[3] = htobe32(1);

    // The A part of S. 
    for(j=0; j<alen; j+=16)
    {
        for(i=0; i<16; i++)
            X[i] = i+j < alen ? ((const uint8_t *)aad)[i+j] : 0;
            
        galois128_hash1block(S, gcm->H, X);
    }

    // The C part of S. 
    for(j=0; j<len; j+=16)
    {
        for(i=0; i<16; i++)
            X[i] = i+j < len ? iptr[i+j] : 0;

        galois128_hash1block(S, gcm->H, X);
    }

    // The len(A) and len(C) part of S. 
    ((uint64_t *)X)[0] = htobe64(alen*8);
    ((uint64_t *)X)[1] = htobe64(len*8);
    galois128_hash1block(S, gcm->H, X);

    // Calculate T. 
    gcm->enc(J0, X, kschd);
    for(i=0; i<4; i++) ((uint32_t *)X)[i] ^= S[i];
    for(i=0; i<tlen; i++) {
        if( ((const uint8_t *)T)[i] != (i<16 ? X[i] : 0) )
            out = NULL;
    }

    if( !out ) return NULL;

    // GCTR: First CB. 
    for(i=0; i<4; i++){ CB[i] = J0[i]; }
    
    // Per rfc5116, actual decryption is here. 
    for(j=0; j<len; j+=16)
    {
        CB[3] = htobe32(be32toh(CB[3])+1);
        gcm->enc(CB, X, kschd);
        
        for(i=0; i<16 && i+j<len; i++) optr[i+j] = iptr[i+j] ^ X[i];
    }

    return out;
}

#define cT(q) (P->param ? P->template(P->param, q) : P->info(q))

IntPtr tGCM(const CryptoParam_t *P, int q)
{
    return cGCM(T,q);
}

void *GCM_T_Init(
    const CryptoParam_t *restrict P,
    gcm_t *restrict x,
    void const *restrict k,
    size_t klen)
{
    if( klen != (size_t)KEY_BYTES(cT) )
        return NULL;
    *x = GCM_INIT(cT);
    KSCHD_FUNC(cT)(k, (char *)x + sizeof(*x));
    x->enc(x->H, x->H, (char *)x + sizeof(*x));
    return x;
}
