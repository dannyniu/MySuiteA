/* DannyNiu/NJF, 2023-10-24. Public Domain. */

#include "mlkem.h"
#include "../1-pq-crystals/m256-codec.h"
#include "../2-hash/sha3.h"
#include "../2-xof/shake.h"
#include "../0-exec/struct-delta.c.h"

static void KPKE_Enc(MLKEM_Ctx_Hdr_t *restrict x, uint8_t m[32], uint8_t r[32])
{
    module256_t tmp1;
    module256_t *Ahat = DeltaTo(x, offset_Ahat);
    module256_t *that = DeltaTo(x, offset_that);
    module256_t *u    = DeltaTo(x, offset_u);
    module256_t *vw   = &x->vw;
    int n = 0, i, j, k = x->k;

    //
    // 1. sample 'r',
    // 2. multiply 'r' with 'A^{hat}' (transposed) and accumulate to 'u',
    // 3. multiply 'r' with 't^{hat}' (row vector) and accumulate to 'vw'.

    for(j=0; j<k; j++)
    {
        // j'th row of the column vector
        MLKEM_SamplePolyCBD(&tmp1, r, n++, x->eta1);
        MLKEM_NTT(&tmp1);

        for(i=0; i<k; i++)
        {
            MLKEM_NttScl(u+i, Ahat+j*k+i, &tmp1, j); // row-major, transposed.
        }

        MLKEM_NttScl(vw, that+j, &tmp1, j);
    }

    for(i=0; i<k; i++)
        MLKEM_InvNTT(u+i);

    MLKEM_InvNTT(vw);

    //
    // sample 'e1' and accumulate to 'u'.

    for(i=0; i<k; i++)
    {
        MLKEM_SamplePolyCBD(&tmp1, r, n++, x->eta2);
        MLKEM_Add(u+i, u+i, &tmp1, false);
    }

    //
    // sample 'e2' and accumulate to 'vw'.

    MLKEM_SamplePolyCBD(&tmp1, r, n++, x->eta2);
    MLKEM_Add(vw, vw, &tmp1, false);

    //
    // convert m to polynomial and add to v.

    Module256DecU(m, 32, &tmp1, 1);
    MLKEM_Decompress(&tmp1, 1);
    MLKEM_Add(vw, vw, &tmp1, false);

    // compress ciphertext.

    for(i=0; i<k; i++)
        MLKEM_Compress(u+i, x->du);

    MLKEM_Compress(vw, x->dv);
}

IntPtr MLKEM_Encode_PublicKey(
    MLKEM_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    module256_t *that = DeltaTo(x, offset_that);
    uint8_t *ptr = enc;
    int i, k = x->k;

    IntPtr ret =
        12 * 32 // single polynomial (12 bits per coefficient),
        * x->k // single vector of polynomial,
        + 32; // seed 'rho' for deriving A^hat.

    if( !enc ) return ret;
    (void)enclen;
    (void)param;

    // ek :: t^hat

    for(i=0; i<k; i++)
    {
        Module256EncU(ptr, 12*32, that+i, 12);
        ptr += 12 * 32;
    }

    // ek :: rho

    for(i=0; i<32; i++)
        *ptr++ = x->rho[i];

    return ret;
}

#if ! PKC_OMIT_PRIV_OPS

#if ! PKC_OMIT_KEYGEN

static void KPKE_Keygen(
    MLKEM_Ctx_Hdr_t *restrict x, uint8_t rho[32], uint8_t sigma[32])
{
    module256_t *Ahat = DeltaTo(x, offset_Ahat);
    module256_t *that = DeltaTo(x, offset_that);
    module256_t *shat = DeltaTo(x, offset_shat);
    module256_t *es   = &x->vw; // scalar / single polynomial.
    int n = 0, i, j, k = x->k;

    for(j=0; j<k; j++)
    {
        for(i=0; i<k; i++)
        {
            MLKEM_SampleNTT(Ahat+i*k+j, rho, i, j); // row-major.
        }
    }

    for(j=0; j<k; j++)
    {
        MLKEM_SamplePolyCBD(shat+j, sigma, n++, x->eta1);
        MLKEM_NTT(shat+j);

        for(i=0; i<k; i++)
            MLKEM_NttScl(that+i, Ahat+i*k+j, shat+j, j);
    }

    for(i=0; i<k; i++)
    {
        MLKEM_SamplePolyCBD(es, sigma, n++, x->eta1);
        MLKEM_NTT(es);
        MLKEM_Add(that+i, that+i, es, false);
    }
}

IntPtr MLKEM_Keygen(
    MLKEM_Ctx_Hdr_t *restrict x, CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    uint8_t seed[12*32];
    sha3_t hctx;
    sha3_512_t *hctx_G = &hctx;
    sha3_256_t *hctx_H = &hctx;
    module256_t *that;
    int i, k;

    if( !x ) return MLKEM_CTX_SIZE_X(param[0].aux);
    *x = MLKEM_CTX_INIT(param[0].aux);
    that = DeltaTo(x, offset_that);
    k = x->k;

    prng_gen(prng, x->z, 32);
    prng_gen(prng, seed, 32);

    // Note from DannyNiu/NJF:
    // I'd rather prefer generating rho and sigma directly from TRNG.
    SHA3_512_Init(hctx_G);
    SHA3_512_Update(hctx_G, seed, 32);
    SHA3_512_Final(hctx_G, seed, 64);

    for(i=0; i<32; i++) x->rho[i] = seed[i];
    KPKE_Keygen(x, seed+0, seed+32);

    SHA3_256_Init(hctx_H);

    for(i=0; i<k; i++)
    {
        Module256EncU(seed, 12*32, that+i, 12);
        SHA3_256_Update(hctx_H, seed, 12*32);
    }
    SHA3_256_Update(hctx_H, x->rho, 32);
    SHA3_256_Final(hctx_H, x->Hek, 32);

    return (IntPtr)x;
}

#endif /* ! PKC_OMIT_KEYGEN */

IntPtr MLKEM_Encode_PrivateKey(
    MLKEM_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    module256_t *that = DeltaTo(x, offset_that);
    module256_t *shat = DeltaTo(x, offset_shat);
    uint8_t *ptr = enc;
    int i, k = x->k;

    IntPtr ret =
        12 * 32 // single polynomial (12 bits per coefficient),
        * x->k // single vector of polynomial,
        * 2 // private key consist of both decryption and encryption key.
        + 32 // seed 'rho' for deriving A^hat.
        + 32 // hash of the public key.
        + 32; // implicit rejection seed.

    if( !enc ) return ret;
    (void)enclen;
    (void)param;

    // dk_pke.

    for(i=0; i<k; i++)
    {
        Module256EncU(ptr, 12*32, shat+i, 12);
        ptr += 12 * 32;
    }

    // ek :: t^hat

    for(i=0; i<k; i++)
    {
        Module256EncU(ptr, 12*32, that+i, 12);
        ptr += 12 * 32;
    }

    // ek :: rho

    for(i=0; i<32; i++)
        *ptr++ = x->rho[i];

    // H(ek)

    for(i=0; i<32; i++)
        *ptr++ = x->Hek[i];

    // z

    for(i=0; i<32; i++)
        *ptr++ = x->z[i];

    return ret;
}

IntPtr MLKEM_Decode_PrivateKey(
    MLKEM_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    module256_t *Ahat;
    module256_t *that;
    module256_t *shat;
    uint8_t const *ptr = enc;
    int i, j, k;

    IntPtr ret = MLKEM_CTX_SIZE(param[0].aux);

    if( !x ) return ret;
    (void)enclen;

    *x = MLKEM_CTX_INIT(param[0].aux);
    Ahat = DeltaTo(x, offset_Ahat);
    that = DeltaTo(x, offset_that);
    shat = DeltaTo(x, offset_shat);
    k = x->k;

    // dk_pke.

    for(i=0; i<k; i++)
    {
        Module256DecU(ptr, 12*32, shat+i, 12);
        ptr += 12 * 32;
    }

    // ek :: t^hat

    for(i=0; i<k; i++)
    {
        Module256DecU(ptr, 12*32, that+i, 12);
        ptr += 12 * 32;
    }

    // ek :: rho

    for(i=0; i<32; i++)
        x->rho[i] = *ptr++;

    for(j=0; j<k; j++)
    {
        for(i=0; i<k; i++)
        {
            MLKEM_SampleNTT(Ahat+i*k+j, x->rho, i, j); // row-major.
        }
    }

    // H(ek)

    for(i=0; i<32; i++)
        x->Hek[i] = *ptr++;

    // z

    for(i=0; i<32; i++)
        x->z[i] = *ptr++;

    return ret;
}

static void KPKE_Dec(MLKEM_Ctx_Hdr_t *restrict x)
{
    module256_t tmp1;
    module256_t *shat = DeltaTo(x, offset_shat);
    module256_t *u    = DeltaTo(x, offset_u);
    module256_t *vw   = &x->vw;
    int i, k = x->k;

    //
    // compute {s^{hat}}^T times u in NTT domain.

    for(i=0; i<k; i++)
    {
        MLKEM_Decompress(u+i, x->du);
        MLKEM_NTT(u+i);
        MLKEM_NttScl(&tmp1, shat+i, u+i, i);
    }

    //
    // NTT^{-1}.

    MLKEM_InvNTT(&tmp1);

    //
    // compute the ciphertext represented in polynomial form.

    MLKEM_Decompress(vw, x->dv);
    MLKEM_Sub(vw, vw, &tmp1);
    MLKEM_Compress(vw, 1);
}

void *MLKEM_Dec(
    MLKEM_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen)
{
    uint8_t cs[64];
    uint8_t ct[64];
    union {
        shake_t xof;
        sha3_t hash;
    } hctx_union;
    shake256_t *hctx = &hctx_union.xof;
    sha3_512_t *hctx_G = &hctx_union.hash;
    module256_t *u    = DeltaTo(x, offset_u);
    module256_t *vw   = &x->vw;
    int i, cc;

    assert( x->status >= 0 );

    if( x->status > 0 )
    {
    finish:
        if( !ss )
        {
            *sslen = 32;
            return NULL;
        }
        else
        {
            for(i=0; (size_t)i<*sslen; i++)
                ((uint8_t *)ss)[i] = i<32 ? x->ss[i] : 0;
            return ss;
        }
    }

    // x->ss is set to the implicit rejection key K^bar
    // by the ciphertext decoder.

    // ciphertext comparison: the loaded one, hashed in ``cs''.
    SHAKE256_Init(hctx);
    SHAKE_Write(hctx, u, sizeof(module256_t) * x->k);
    SHAKE_Write(hctx, vw, sizeof(module256_t));
    SHAKE_Final(hctx);
    SHAKE_Read(hctx, cs, x->k*16);

    // K-PKE.Decrypt.
    KPKE_Dec(x);
    Module256EncU(ct, 32, vw, 1); // ct is now m'.

    // (K',r') := G(m'||h).
    SHA3_512_Init(hctx_G);
    SHA3_512_Update(hctx_G, ct, 32);
    SHA3_512_Update(hctx_G, x->Hek, 32);
    SHA3_512_Final(hctx_G, x->tup, 64);

    // c' := K-PKE.Encrypt.
    KPKE_Enc(x, ct, x->tup+32);

    // ciphertext comparision: the reproduced one, hased in ``ct''.
    SHAKE256_Init(hctx);
    SHAKE_Write(hctx, u, sizeof(module256_t) * x->k);
    SHAKE_Write(hctx, vw, sizeof(module256_t));
    SHAKE_Final(hctx);
    SHAKE_Read(hctx, ct, x->k*16);

    cc = 0;
    for(i=0; i<x->k*16; i++) cc |= cs[i] ^ ct[i];
    cc |= cc >> 4;
    cc |= cc >> 2;
    cc |= cc >> 1;
    cc &= 1;
    cc = -cc;

    for(i=0; i<32; i++)
        x->ss[i] = (x->ss[i] & cc) | (x->tup[i] & ~cc);

    x->status = 1;
    goto finish;
}

void *MLKEM_Decode_Ciphertext(
    MLKEM_Ctx_Hdr_t *restrict x,
    void const *restrict ct, size_t ctlen)
{
    module256_t *u    = DeltaTo(x, offset_u);
    module256_t *vw   = &x->vw;
    uint8_t const *ptr = ct;
    int i, k = x->k, du = x->du, dv = x->dv;

    shake_t hctx_xof;
    shake256_t *hctx_J = &hctx_xof;

    SHAKE256_Init(hctx_J);
    SHAKE_Write(hctx_J, x->z, 32);
    SHAKE_Write(hctx_J, ct, ctlen);
    SHAKE_Final(hctx_J);
    SHAKE_Read(hctx_J, x->ss, 32);

    for(i=0; i<k; i++)
    {
        Module256DecU(ptr, du*32, u+i, du);
        ptr += du*32;
    }

    Module256DecU(ptr, dv*32, vw, dv);
    x->status = 0;
    return x;
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

void *MLKEM_Encode_Ciphertext(
    MLKEM_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t *ctlen)
{
    module256_t *u    = DeltaTo(x, offset_u);
    module256_t *vw   = &x->vw;
    uint8_t *ptr = ct;
    int i, k = x->k, du = x->du, dv = x->dv;

    size_t sslen_expected = 32 * (k * du + dv);

    if( !ct )
    {
        *ctlen = sslen_expected;
        return NULL;
    }

    for(i=0; i<k; i++)
    {
        Module256EncU(ptr, du*32, u+i, du);
        ptr += du*32;
    }

    Module256EncU(ptr, dv*32, vw, dv);
    return ct;
}

IntPtr MLKEM_Decode_PublicKey(
    MLKEM_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    sha3_t hctx;
    sha3_256_t *hctx_H = &hctx;
    module256_t *Ahat;
    module256_t *that;
    uint8_t const *ptr = enc;
    int i, j, k;

    IntPtr ret = MLKEM_CTX_SIZE(param[0].aux);

    if( !x ) return ret;

    *x = MLKEM_CTX_INIT(param[0].aux);
    Ahat = DeltaTo(x, offset_Ahat);
    that = DeltaTo(x, offset_that);
    k = x->k;

    // ek :: t^hat
    for(i=0; i<k; i++)
    {
        Module256DecU(ptr, 12*32, that+i, 12);
        ptr += 12 * 32;
    }

    // ek :: rho
    for(i=0; i<32; i++)
        x->rho[i] = *ptr++;

    for(j=0; j<k; j++)
    {
        for(i=0; i<k; i++)
        {
            MLKEM_SampleNTT(Ahat+i*k+j, x->rho, i, j); // row-major.
        }
    }

    // H(ek)

    SHA3_256_Init(hctx_H);
    SHA3_256_Update(hctx_H, enc, enclen);
    SHA3_256_Final(hctx_H, x->Hek, 32);

    return ret;
}

void *MLKEM_Enc(
    MLKEM_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng)
{
    union {
        sha3_t hash;
        shake_t xof;
    } hctx;
    sha3_512_t *hctx_G = &hctx.hash;
    shake256_t *hctx_preproc = &hctx.xof;
    int i;

    if( !ss )
    {
        *sslen = 32;
        return NULL;
    }

    // Although NIST said that only approved RNGs can be used to sample
    // the initial message 'm' and thus hashing in unnecessary, we take
    // operative liberty to insist on hashing a longer RNG output into the
    // initial message 'm', as it ultimately does not hurt interoperability.
    prng_gen(prng, x->tup, 64);

    SHAKE256_Init(hctx_preproc);
    SHAKE_Write(hctx_preproc, x->tup, 64);
    SHAKE_Final(hctx_preproc);
    SHAKE_Read(hctx_preproc, x->ss, 32);

    SHA3_512_Init(hctx_G);
    SHA3_512_Update(hctx_G, x->ss, 32);
    SHA3_512_Update(hctx_G, x->Hek, 32);
    SHA3_512_Final(hctx_G, x->tup, 64);

    KPKE_Enc(x, x->ss, x->tup+32);
    for(i=0; i<32; i++) x->ss[i] = x->tup[i];
    for(i=0; (size_t)i<*sslen; i++)
        ((uint8_t *)ss)[i] = i < 32 ? x->ss[i] : 0;

    return ss;
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS)

IntPtr iMLKEM_KeyCodec(int q) { return xMLKEM_KeyCodec(q); }

IntPtr tMLKEM(const CryptoParam_t *P, int q)
{
    return xMLKEM(P[0].aux, q);
}

IntPtr iMLKEM_CtCodec(int q) { return xMLKEM_CtCodec(q); }

#endif /* ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS) */
