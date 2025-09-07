/* DannyNiu/NJF, 2018-02-11. Public Domain. */

#include "gcm.h"
#include "../1-symm/galois128.h"
#include "../0-exec/struct-delta.c.h"
#include "../0-datum/endian.h"

void *GCM_Encrypt(gcm_t *restrict gcm,
                  size_t ivlen, void const *iv,
                  size_t alen, void const *aad,
                  size_t len, void const *in, void *out,
                  size_t tlen, void *T)
{
    size_t i, j;
    void (*ghash128)(
        void *restrict Y,
        void const *restrict H,
        void const *restrict X) =
        galois128_hash1block;

    alignas(16) uint32_t
        J0[4],
        CB[4],
        S[4] = {0};
    alignas(16) uint8_t X[16];
    const uint8_t *iptr = in; uint8_t *optr = out;

    void *kschd = DeltaTo(gcm, offset);

    // values taken from
    // https://www.rfc-editor.org/rfc/rfc5116.html#section-5.3
    if( ivlen != 12 ||
        (uintmax_t)alen >= (uint64_t)1 << 61 ||
        (uintmax_t)len >= ((uint64_t)1 << 36) - 31 )
        return NULL;

    // Prepare J0.
    for(i=0; i<3; i++){ J0[i] = ((const uint32_t *)iv)[i]; } J0[3] = htobe32(1);

    // The A part of S.
    for(j=0; j<alen; j+=16)
    {
        for(i=0; i<16; i++)
            X[i] = i+j < alen ? ((const uint8_t *)aad)[i+j] : 0;

        ghash128(S, gcm->H, X);
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

        ghash128(S, gcm->H, X);
    }

    // The len(A) and len(C) part of S.
    ((uint64_t *)X)[0] = htobe64(alen*8);
    ((uint64_t *)X)[1] = htobe64(len*8);
    ghash128(S, gcm->H, X);

    // Calculate T. Zero-extends if tlen>16.
    gcm->enc(J0, X, kschd);
    for(i=0; i<4; i++) ((uint32_t *)X)[i] ^= S[i];
    for(i=0; i<tlen; i++) ((uint8_t *)T)[i] = i<16 ? X[i] : 0;

    return out;
}

void *GCM_Decrypt(gcm_t *restrict gcm,
                  size_t ivlen, void const *iv,
                  size_t alen, void const *aad,
                  size_t len, void const *in, void *out,
                  size_t tlen, void const *T)
{
    int b;
    size_t i, j;
    void (*ghash128)(
        void *restrict Y,
        void const *restrict H,
        void const *restrict X) =
        galois128_hash1block;

    alignas(16) uint32_t
        J0[4],
        CB[4],
        S[4] = {0};
    alignas(16) uint8_t X[16];
    const uint8_t *iptr = in; uint8_t *optr = out;

    void *kschd = DeltaTo(gcm, offset);

    // values taken from
    // https://www.rfc-editor.org/rfc/rfc5116.html#section-5.3
    if( ivlen != 12 ||
        (uintmax_t)alen >= (uint64_t)1 << 61 ||
        (uintmax_t)len >= ((uint64_t)1 << 36) - 31 )
        return NULL;

    // Prepare J0.
    for(i=0; i<3; i++)
    {
        J0[i] = ((const uint32_t *)iv)[i];
    }
    J0[3] = htobe32(1);

    // The A part of S.
    for(j=0; j<alen; j+=16)
    {
        for(i=0; i<16; i++)
            X[i] = i+j < alen ? ((const uint8_t *)aad)[i+j] : 0;

        ghash128(S, gcm->H, X);
    }

    // The C part of S.
    for(j=0; j<len; j+=16)
    {
        for(i=0; i<16; i++)
            X[i] = i+j < len ? iptr[i+j] : 0;

        ghash128(S, gcm->H, X);
    }

    // The len(A) and len(C) part of S.
    ((uint64_t *)X)[0] = htobe64(alen*8);
    ((uint64_t *)X)[1] = htobe64(len*8);
    ghash128(S, gcm->H, X);

    // Calculate T.
    b = 0;
    gcm->enc(J0, X, kschd);
    for(i=0; i<4; i++) ((uint32_t *)X)[i] ^= S[i];
    for(i=0; i<tlen; i++)
    {
        b |= ((const uint8_t *)T)[i] ^ (i<16 ? X[i] : 0);
    }
    if( b ) return NULL;

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

#define cT(q) (P->param ? P->factory(P->param, q) : P->info(q))

IntPtr tGCM(const CryptoParam_t *P, int q) { return xGCM(T,q); }

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
