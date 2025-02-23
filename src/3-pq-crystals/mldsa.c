/* DannyNiu/NJF, 2023-09-22. Public Domain. */

#include "mldsa.h"
#include "../1-pq-crystals/m256-codec.h"
#include "../2-xof/shake.h"
#include "../2-hash/hash-dgst-oid-table.h"
#include "../0-exec/struct-delta.c.h"
#include "../0-datum/endian.h"

static inline int32_t Tau(const int kp, const int lp)
{
    return
        kp == 4 && lp == 4 ? 39 :
        kp == 6 && lp == 5 ? 49 :
        kp == 8 && lp == 7 ? 60 : -1;
}

static inline int32_t Eta(const int kp, const int lp)
{
    return
        kp == 4 && lp == 4 ? 2  :
        kp == 6 && lp == 5 ? 4  :
        kp == 8 && lp == 7 ? 2  : -1;
}

static inline int32_t Beta(const int kp, const int lp)
{
    int32_t m1 = Tau(kp, lp), m2 = Eta(kp, lp);
    if( m1 < 0 || m2 < 0 ) return -1; else return m1 * m2;
}

static inline int32_t Omega(const int kp, const int lp)
{
    return
        kp == 4 && lp == 4 ? 80 :
        kp == 6 && lp == 5 ? 55 :
        kp == 8 && lp == 7 ? 75 : -1;
}

static inline int32_t log2_Gamma1(const int kp, const int lp)
{
    return
        kp == 4 && lp == 4 ? 17 :
        kp == 6 && lp == 5 ? 19 :
        kp == 8 && lp == 7 ? 19 : -1;
}

static inline int32_t Gamma2(const int kp, const int lp)
{
    return
        kp == 4 && lp == 4 ? (MLDSA_Q - 1) / 88 :
        kp == 6 && lp == 5 ? (MLDSA_Q - 1) / 32 :
        kp == 8 && lp == 7 ? (MLDSA_Q - 1) / 32 : -1;
}

#define TAU Tau(x->k, x->l)
#define ETA Eta(x->k, x->l)
#define BETA Beta(x->k, x->l)
#define OMEGA Omega(x->k, x->l)
#define LOG2_GAMMA1 log2_Gamma1(x->k, x->l)
#define GAMMA2 Gamma2(x->k, x->l)

static void *MLDSA_MsgHash_Prelude(
    const uint8_t tr[64], const uint8_t ctxstr[256],
    const hash_funcs_set_t hfuncs, UpdateFunc_t *placeback,
    shake256_t *muctx, void *phctx, int32_t oind)
{
    uint8_t b;
    SHAKE256_Init(muctx);
    SHAKE_Write(muctx, tr, 64);

    if( hfuncs.initfunc )
    {
        if( oind < 0 || !hash_dgst_oids[oind].oid )
            return NULL;

        b = 1;
        SHAKE_Write(muctx, &b, 1);
        SHAKE_Write(muctx, ctxstr, ctxstr[0] + 1);
        SHAKE_Write(
            muctx,
            hash_dgst_oids[oind].oid,
            hash_dgst_oids[oind].oidlen);

        hfuncs.initfunc(phctx);
        *placeback = hfuncs.updatefunc;
        return phctx;
    }
    else
    {
        b = 0;
        SHAKE_Write(muctx, &b, 1);
        SHAKE_Write(muctx, ctxstr, ctxstr[0] + 1);
        *placeback = (UpdateFunc_t)SHAKE_Write;
        return muctx;
    }
}

static void MLDSA_MsgHash_Postlude(
    uint8_t mu[64], size_t hashlen,
    const hash_funcs_set_t hfuncs,
    shake256_t *muctx, void *phctx)
{
    if( hfuncs.initfunc )
    {
        if( hfuncs.xfinalfunc )
            hfuncs.xfinalfunc(phctx);
        hfuncs.hfinalfunc(phctx, mu, hashlen);

        SHAKE_Write(muctx, mu, hashlen);
    }

    SHAKE_Final(muctx);
    SHAKE_Read(muctx, mu, 64);
}

static void SampleInBall(
    module256_t *restrict c,
    const uint8_t seed[],
    int32_t seedlen, int tau)
{
    shake_t hctx;
    uint8_t signs[8];
    int i, j, k;
    uint8_t b;

    for(i=0; i<256; i++) c->r[i] = 0;

    SHAKE256_Init(&hctx);
    SHAKE_Write(&hctx, seed, seedlen);
    SHAKE_Final(&hctx);

    SHAKE_Read(&hctx, signs, 8);

    for(i=256-tau; i<256; i++)
    {
        do
        {
            SHAKE_Read(&hctx, &b, 1);
            j = b;
        }
        while( j > i );

        k = i + tau - 256;
        k = signs[k/8] >> (k%8);
        k &= 1;

        c->r[i] = c->r[j];
        c->r[j] = 1 | ((uint32_t)-1 * k);
    }
}

#if ! PKC_OMIT_PRIV_OPS

#if ! PKC_OMIT_KEYGEN

IntPtr MLDSA_Keygen(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng)
{
    uint8_t xi[34];
    shake_t hctx, h_tr;
    module256_t *m, *t, *a;
    int i, r, s;
    int k, l;

    if( !x )
    {
        return MLDSA_PRIV_CTX_SIZE(
            param[0].aux, param[1].aux, param[2].info);
    }

    *x = MLDSA_PRIV_CTX_INIT(param[0].aux, param[1].aux, param[2].info);
    k = x->k, l = x->l;

    prng_gen(prng, xi, 32);
    xi[32] = x->k;
    xi[33] = x->l;

    SHAKE256_Init(&hctx);
    SHAKE_Write(&hctx, xi, 34);
    SHAKE_Final(&hctx);

    // A^hat := ExpandA(rho)

    SHAKE_Read(&hctx, x->rho, 32);
    a = DeltaTo(x, offset_Ahat);

    for(r=0; r<k; r++)
    {
        for(s=0; s<l; s++)
        {
            MLDSA_RejNTTPoly(a+r*l+s, x->rho, s, r); // row-major.
        }
    }

    // (s_1, s_2) := ExpandS(rho')

    SHAKE_Read(&hctx, x->tr, 64); // reuse a little bit.

    // s1/s2 order reversed to avoid 1 offset re-calculation.
    m = DeltaTo(x, offset_s2hat);
    for(i=0; i<k; i++)
    {
        MLDSA_RejBoundedPoly(m+i, x->tr, i+l, ETA);
        MLDSA_NTT(m+i);
    }

    m = DeltaTo(x, offset_s1hat);
    for(i=0; i<l; i++)
    {
        MLDSA_RejBoundedPoly(m+i, x->tr, i, ETA);
        MLDSA_NTT(m+i);
    }

    // t := A*s_1 + s_2

    t = DeltaTo(x, offset_t1);
    for(r=0; r<k; r++)
    {
        for(s=0; s<l; s++)
        {
            MLDSA_NttScl(t+r, m+s, a+r*l+s, s);
        }
    }

    m = DeltaTo(x, offset_s2hat);
    for(r=0; r<k; r++)
    {
        MLDSA_Add(t+r, t+r, m+r, false);
        MLDSA_InvNTT(t+r);
    }

    // (t_1, t_0) := Power2Round(t, d/*13*/)
    // pk := pkEncode(rho, t_1)

    SHAKE256_Init(&h_tr);
    SHAKE_Write(&h_tr, x->rho, 32);

    m = DeltaTo(x, offset_t0hat);
    for(r=0; r<k; r++)
    {
        for(s=0; s<256; s++)
            t[r].r[s] = MLDSA_Power2Round(t[r].r[s], &m[r].r[s], MLDSA_D);

        Module256EncU(
            (void *)x->c.r,
            320, t+r, 10); // 256 x 10 bits per coefficient / 8 bits per byte.

        MLDSA_NTT(m+r);

        SHAKE_Write(&h_tr, x->c.r, 320);
    }

    SHAKE_Final(&h_tr);
    SHAKE_Read(&h_tr, x->tr, 64);

    // K := substr(H(xi), 96, 32)

    SHAKE_Read(&hctx, x->K, 32);

    // Added 2024-10-22, get OID for pre-hash.
    if( (x->hash_oid_tab_ind = MsgHash_FindOID(
             &x->hfuncs, DeltaTo(x, offset_hashctx))) == -1 )
        return (IntPtr)NULL;

    return (IntPtr)x;
}

#endif /* ! PKC_OMIT_KEYGEN */

IntPtr MLDSA_Encode_PrivateKey(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    module256_t *m;
    uint8_t *ptr = enc;
    int i, r, s;

    IntPtr encsz;
    int k = x->k, l = x->l;

    assert( ETA == 2 || ETA == 4);
    r = ETA / 2 + 2; // 2023-11-18: should be ``+ 2'', was ``+ 3''.
    encsz = 32 * (4 + (k + l) * r + k * MLDSA_D);

    (void)param;
    if( !enc ) goto done;
    if( (IntPtr)enclen < encsz ) return -1;

    for(i=0; i<32; i++)
    {
        ptr[i +  0] = x->rho[i];
        ptr[i + 32] = x->K[i];
        ptr[i + 64] = x->tr[i];
        ptr[i + 96] = x->tr[i + 32];
    }

    m = DeltaTo(x, offset_s1hat);
    for(i=0; i<l; i++)
    {
        for(s=0; s<256; s++)
            x->c.r[s] = m[i].r[s];

        MLDSA_InvNTT(&x->c);
        for(s=0; s<256; s++)
            x->c.r[s] = MLDSA_UModQ(ETA - x->c.r[s]);

        Module256EncU(
            ptr + 128 + i * 32 * r,
            32 * r, &x->c, r);
    }

    m = DeltaTo(x, offset_s2hat);
    for(i=0; i<k; i++)
    {
        for(s=0; s<256; s++)
            x->c.r[s] = m[i].r[s];

        MLDSA_InvNTT(&x->c);
        for(s=0; s<256; s++)
            x->c.r[s] = MLDSA_UModQ(ETA - x->c.r[s]);

        Module256EncU(
            ptr + 128 + (i + l) * 32 * r,
            32 * r, &x->c, r);
    }

    m = DeltaTo(x, offset_t0hat);
    for(i=0; i<k; i++)
    {
        for(s=0; s<256; s++)
            x->c.r[s] = m[i].r[s];

        MLDSA_InvNTT(&x->c);
        for(s=0; s<256; s++)
            x->c.r[s] = MLDSA_UModQ((1<<(MLDSA_D-1)) - x->c.r[s]);

        Module256EncU(
            ptr + 128 + ((l + k) * r + i * MLDSA_D) * 32,
            32 * MLDSA_D, &x->c, MLDSA_D);
    }

done:
    return encsz;
}

IntPtr MLDSA_Decode_PrivateKey(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    module256_t *m, *t, *a;
    uint8_t const *ptr = enc;
    int i, r, s;

    IntPtr encsz;
    int k, l;

    if( !x ) goto done;

    *x = MLDSA_PRIV_CTX_INIT(param[0].aux, param[1].aux, param[2].info);
    k = x->k, l = x->l;

    assert( ETA == 2 || ETA == 4);
    r = ETA / 2 + 2; // 2023-11-18: should be ``+ 2'', was ``+ 3''.
    encsz = 32 * (4 + (k + l) * r + k * MLDSA_D);
    if( (IntPtr)enclen < encsz ) return -1;

    for(i=0; i<32; i++)
    {
        x->rho[i] = ptr[i +  0];
        x->K  [i] = ptr[i + 32];
        x->tr [i] = ptr[i + 64];
        x->tr [i + 32] = ptr[i + 96];
    }

    a = DeltaTo(x, offset_Ahat);
    for(r=0; r<k; r++)
    {
        for(s=0; s<l; s++)
        {
            MLDSA_RejNTTPoly(a+r*l+s, x->rho, s, r);
        }
    }

    // re-computed.
    r = ETA / 2 + 2; // 2023-11-18: should be ``+ 2'', was ``+ 3''.

    // s1/s2 order reversed to avoid 1 offset re-calculation.
    m = DeltaTo(x, offset_s2hat);
    for(i=0; i<x->k; i++)
    {
        Module256DecU(
            ptr + 128 + (i + l) * 32 * r,
            32 * r, &x->c, r);
        for(s=0; s<256; s++)
            m[i].r[s] = MLDSA_UModQ(ETA - (int64_t)x->c.r[s]);
        MLDSA_NTT(m+i);
    }

    m = DeltaTo(x, offset_s1hat);
    for(i=0; i<x->l; i++)
    {
        Module256DecU(
            ptr + 128 + i * 32 * r,
            32 * r, &x->c, r);
        for(s=0; s<256; s++)
            m[i].r[s] = MLDSA_UModQ(ETA - (int64_t)x->c.r[s]);
        MLDSA_NTT(m+i);
    }

    // 2023-10-02:
    // Re-run keygen to obtain relevant public key components,
    // as the recovery of those components are missing in the
    // technical specification. This will allow re-exporting
    // of the public key.

    // t := A*s_1 + s_2

    t = DeltaTo(x, offset_t1);
    for(r=0; r<k; r++)
    {
        for(s=0; s<l; s++)
        {
            MLDSA_NttScl(t+r, m+s, a+r*l+s, s);
        }
    }

    m = DeltaTo(x, offset_s2hat);
    for(r=0; r<k; r++)
    {
        MLDSA_Add(t+r, t+r, m+r, false);
        MLDSA_InvNTT(t+r);
    } // t is in R (polynomial domain).

    // (t_1, t_0) := Power2Round(t, d/*13*/)

    m = DeltaTo(x, offset_t0hat);
    for(r=0; r<k; r++)
    {
        for(s=0; s<256; s++)
            t[r].r[s] = MLDSA_Power2Round(t[r].r[s], &m[r].r[s], MLDSA_D);

        MLDSA_NTT(m+r);
    }

    // Added 2024-10-22, get OID for pre-hash.
    if( (x->hash_oid_tab_ind = MsgHash_FindOID(
             &x->hfuncs, DeltaTo(x, offset_hashctx))) == -1 )
        return -1;

done:
    return MLDSA_PRIV_CTX_SIZE(param[0].aux, param[1].aux, param[2].info);
}

IntPtr MLDSA_Export_PublicKey(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    module256_t *t1;
    uint8_t *ptr = enc;
    int i;

    // 320 := 256 x 10 bits per coefficient / 8 bits per byte.
    IntPtr encsz = 32 + (IntPtr)x->k * 320;

    (void)param;
    if( !enc ) goto done;
    if( (IntPtr)enclen < encsz ) return -1;

    for(i=0; i<32; i++)
        ptr[i] = x->rho[i];

    ptr += 32;

    t1 = DeltaTo(x, offset_t1); // in polynomial domain.
    for(i=0; i<x->k; i++)
    {
        Module256EncU(ptr + 320*i, 320, t1+i, 10);
    }

done:
    return encsz;
}

static void *Dilithium_Sign(
    MLDSA_Priv_Ctx_Hdr_t *restrict x, const uint8_t mu[64],
    GenFunc_t prng_gen, void *restrict prng);

void *MLDSA_Sign(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng)
{
    uint8_t mu[64];
    shake256_t hctx;
    void *msghash;
    UpdateFunc_t update;

    if( !(msghash = MLDSA_MsgHash_Prelude(
              x->tr, x->ctxstr, x->hfuncs, &update,
              &hctx, DeltaTo(x, offset_hashctx),
              x->hash_oid_tab_ind)) )
        return NULL;

    update(msghash, msg, msglen);

    MLDSA_MsgHash_Postlude(
        mu, x->hashlen, x->hfuncs,
        &hctx, DeltaTo(x, offset_hashctx));

    return Dilithium_Sign(x, mu, prng_gen, prng);
}

void *MLDSA_IncSign_Init(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback)
{
    static_assert( sizeof(shake256_t) < sizeof(x->c),
                   "Borrowed object too small" );

    return MLDSA_MsgHash_Prelude(
        x->tr, x->ctxstr, x->hfuncs, placeback,
        (void *)&x->c, DeltaTo(x, offset_hashctx),
        x->hash_oid_tab_ind);
}

void *MLDSA_IncSign_Final(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen,
    void *restrict prng)
{
    uint8_t mu[64];

    MLDSA_MsgHash_Postlude(
        mu, x->hashlen, x->hfuncs,
        (void *)&x->c, DeltaTo(x, offset_hashctx));

    return Dilithium_Sign(x, mu, prng_gen, prng);
}

static void *Dilithium_Sign( // 2024-08-31: "internal" routine.
    MLDSA_Priv_Ctx_Hdr_t *restrict x, const uint8_t mu[64],
    GenFunc_t prng_gen, void *restrict prng)
{
    uint8_t rho_apos[64];
    uint8_t rnd[32];
    shake_t hctx;
    module256_t *Ahat  = DeltaTo(x, offset_Ahat);
    module256_t *s1hat = DeltaTo(x, offset_s1hat);
    module256_t *s2hat = DeltaTo(x, offset_s2hat);
    module256_t *t0hat = DeltaTo(x, offset_t0hat);
    module256_t *yz    = DeltaTo(x, offset_yz);
    module256_t *w     = DeltaTo(x, offset_w);
    module256_t *cs    = DeltaTo(x, offset_cs);
    module256_t *ck    = cs + 0;
    module256_t *cl    = cs + x->k;

    int32_t t;
    int kappa;
    int r, s;
    int k = x->k, l = x->l;

    // mu hashing.

    if( prng_gen && prng )
    {
        prng_gen(prng, rnd, 32);
    }
    else
    {
        for(t=0; t<32; t++) rnd[t] = 0;
    }

    SHAKE256_Init(&hctx);
    SHAKE_Write(&hctx, x->K, 32);
    SHAKE_Write(&hctx, rnd, 32);
    SHAKE_Write(&hctx, mu, 64);
    SHAKE_Final(&hctx);
    SHAKE_Read(&hctx, rho_apos, 64);

    kappa = -1;

start:
    if( kappa == -1 ) kappa = 0;
    else kappa += l;

    // sample y.

    for(s=0; s<l; s++)
    {
        MLDSA_ExpandMask_1Poly(yz+s, rho_apos, s, LOG2_GAMMA1, kappa);
        MLDSA_NTT(yz+s);
    }

    // compute w.

    for(r=0; r<k; r++)
    {
        for(s=0; s<l; s++)
        {
            MLDSA_NttScl(w+r, yz+s, Ahat+r*l+s, s); // row-major.
        }
        MLDSA_InvNTT(w+r);
    }

    // HighBits(w).

    for(r=0; r<k; r++)
    {
        for(s=0; s<256; s++)
            ck[r].r[s] = MLDSA_Decompose(w[r].r[s], NULL, GAMMA2);
    }

    // w1Encode.

    SHAKE256_Init(&hctx);
    SHAKE_Write(&hctx, mu, 64);

    assert( GAMMA2 == (MLDSA_Q-1)/88 || GAMMA2 == (MLDSA_Q-1)/32 );
    t     = GAMMA2 == (MLDSA_Q-1)/88 ? 6 : 4;
    for(r=0; r<k; r++)
    {
        // t is coeffbits.

        Module256EncU((void *)&x->c, t*32, ck + r, t);
        SHAKE_Write(&hctx, &x->c, t*32);
    }

    SHAKE_Final(&hctx);
    SHAKE_Read(&hctx, x->challenge, k*8);

    // chat, <<cs1>>, and <<cs2>>.
    // simultaneously: z := y + <<cs1>> and r0 := LowBis(w - <<cs2>>).

    SampleInBall(&x->c, x->challenge, k*8, TAU);
    MLDSA_NTT(&x->c);

    for(s=0; s<l; s++)
    {
        MLDSA_NttScl(cl+s, &x->c, s1hat+s, false);
        MLDSA_Add(yz+s, yz+s, cl+s, false);
        MLDSA_InvNTT(yz+s);
    }

    for(r=0; r<k; r++)
    {
        MLDSA_NttScl(ck+r, &x->c, s2hat+r, false);
        MLDSA_InvNTT(ck+r);
        MLDSA_Sub(w+r, w+r, ck+r);
    }

    // if coefficient overflow, then restart.

    t = ((int32_t)1 << LOG2_GAMMA1) - BETA;
    for(s=0; s<l; s++)
    {
        if( MLDSA_HasOverflow(yz+s, t) ) goto start;

        // make ``yz'' ready for bit packing. in R (polynomial domain).
        for(r=0; r<256; r++)
            yz[s].r[r] = MLDSA_UModQ(
                ((int64_t)1 << LOG2_GAMMA1) - yz[s].r[r]);
    }

    t = GAMMA2 - BETA;
    for(r=0; r<k; r++)
    {
        for(s=0; s<256; s++)
            MLDSA_Decompose(w[r].r[s], &cl->r[s], GAMMA2);

        if( MLDSA_HasOverflow(cl, t) ) goto start;
    }

    // <<ct0>> := InvNTT(chat o t0hat).
    // then: w - <<cs2>> (already computed so far) + <<ct0>>

    t=0;
    for(r=0; r<k; r++)
    {
        MLDSA_NttScl(ck+r, &x->c, t0hat+r, false);
        MLDSA_InvNTT(ck+r);
        if( MLDSA_HasOverflow(ck+r, GAMMA2) ) goto start;

        // Commented-out since implemented slightly differently:
        // MLDSA_Add(w+r, w+r, ck+r, false);
        for(s=0; s<256; s++)
        {
            t += w[r].r[s] = MLDSA_MakeHint(
                ck[r].r[s], w[r].r[s], GAMMA2);
        }
    }
    if( t > OMEGA ) goto start;

    x->status = 1;
    return x;
}

static void HintBitPack(
    uint8_t *restrict packed,
    int32_t k, int32_t omega,
    module256_t const h[restrict])
{
    int32_t i, j, index;

    for(i=0; i<k+omega; i++) packed[i] = 0;

    index = 0;
    for(i=0; i<k; i++)
    {
        for(j=0; j<256; j++)
        {
            if( h[i].r[j] )
                packed[index] = j, index++;
        }
        packed[omega+i] = index;
    }
}

void *MLDSA_Encode_Signature(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen)
{
    size_t sigsz;
    uint8_t *ptr = sig;
    int i; // , r, s; // 2 vars not used.
    int k = x->k, l = x->l;

    module256_t *h = DeltaTo(x, offset_w);
    module256_t *z = DeltaTo(x, offset_yz);

    assert( k == 4 || k == 6 || k == 8 );
    sigsz = k * 8 + l * 32 * (LOG2_GAMMA1 + 1) + (OMEGA + k);
    if( !sig )
    {
        *siglen = sigsz;
        return NULL;
    }

    for(i=0; i<k*8; i++)
        ptr[i] = x->challenge[i];

    for(i=0; i<l; i++)
    {
        Module256EncU(
            ptr + k*8 + i * 32 * (LOG2_GAMMA1 + 1),
            32 * (LOG2_GAMMA1 + 1), z+i, LOG2_GAMMA1+1);
    }

    HintBitPack(
        ptr + k*8 + l * 32 * (LOG2_GAMMA1 + 1),
        k, OMEGA, h);

    return sig;
}

void *MLDSA_Sign_Xctrl(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    size_t t;
    (void)flags;

    switch( cmd )
    {
    case MLDSA_set_ctxstr:
        if( !bufvec || veclen < 1 ) return NULL;
        if( bufvec[0].len > 255 ) return NULL;

        x->ctxstr[0] = bufvec[0].len;
        for(t=0; t<bufvec[0].len; t++)
            x->ctxstr[t+1] = ((uint8_t *)bufvec[0].dat)[t];
        return x;
        break;

    default:
        return NULL;
    }
}

#endif /* ! PKC_OMIT_PRIV_OPS */

#if ! PKC_OMIT_PUB_OPS

IntPtr MLDSA_Encode_PublicKey(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    module256_t *t1;
    uint8_t *ptr = enc;
    int i, s;

    // 320 := 256 x 10 bits per coefficient / 8 bits per byte.
    IntPtr encsz = 32 + (IntPtr)x->k * 32*23;//320;

    (void)param;
    if( !enc ) goto done;
    if( (IntPtr)enclen < encsz ) return -1;

    for(i=0; i<32; i++)
        ptr[i] = x->rho[i];

    ptr += 32;

    t1 = DeltaTo(x, offset_t1hat);
    for(i=0; i<x->k; i++)
    {
        for(s=0; s<256; s++)
        {
            x->c.r[s] = t1[i].r[s];
        }
        MLDSA_InvNTT(&x->c);

        for(s=0; s<256; s++)
        {
            x->c.r[s] = MLDSA_UModQ(x->c.r[s]) >> MLDSA_D;
        }
        Module256EncU(ptr + 320*i, 320, t1+i, 10);
    }

done:
    return encsz;
}

IntPtr MLDSA_Decode_PublicKey(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param)
{
    module256_t *t, *a;
    uint8_t const *ptr = enc;

    shake_t hctx;
    int i, r, s;

    IntPtr encsz;
    int k, l;

    if( !x ) goto done;

    *x = MLDSA_PUB_CTX_INIT(param[0].aux, param[1].aux, param[2].info);
    k = x->k, l = x->l;

    // 320 := 256 x 10 bits per coefficient / 8 bits per byte.
    encsz = 32 + (IntPtr)k * 320;

    if( (IntPtr)enclen < encsz ) return -1;

    for(i=0; i<32; i++)
        x->rho[i] = ptr[i];

    ptr += 32;

    SHAKE256_Init(&hctx);
    SHAKE_Write(&hctx, enc, enclen);
    SHAKE_Final(&hctx);
    SHAKE_Read(&hctx, x->tr, 64);

    a = DeltaTo(x, offset_Ahat);
    for(r=0; r<k; r++)
    {
        for(s=0; s<l; s++)
        {
            MLDSA_RejNTTPoly(a+r*l+s, x->rho, s, r);
        }
    }

    t = DeltaTo(x, offset_t1hat);
    for(i=0; i<k; i++)
    {
        Module256DecU(ptr + 320*i, 320, t+i, 10);
        for(s=0; s<256; s++) t[i].r[s] <<= MLDSA_D;
        MLDSA_NTT(t+i);
    } // t is in T (NTT domain).

    // Added 2024-10-22, get OID for pre-hash.
    if( (x->hash_oid_tab_ind = MsgHash_FindOID(
             &x->hfuncs, DeltaTo(x, offset_hashctx))) == -1 )
        return -1;

done:
    return MLDSA_PUB_CTX_SIZE(param[0].aux, param[1].aux, param[2].info);
}

static void *HintBitUnpack(
    uint8_t const *restrict packed,
    int32_t k, int32_t omega,
    module256_t h[restrict])
{
    int32_t i, j, index, first;

    for(i=0; i<k; i++) for(j=0; j<256; j++) h[i].r[j] = 0;

    index = 0;
    for(i=0; i<k; i++)
    {
        if( packed[omega+i] < index || packed[omega+i] > omega )
            return NULL;

        first = index;
        while( index < packed[omega+i] )
        {
            if( index > first )
                if( packed[index-1] > packed[index] )
                    return NULL;

            h[i].r[packed[index]] = 1;
            index++;
        }
    }

    while( index < omega ){ if( packed[index++] ) return NULL; }
    return h;
}

void *MLDSA_Decode_Signature(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict sig, size_t siglen)
{
    size_t sigsz;
    uint8_t const *ptr = sig;
    int32_t t;
    int i, s; // ``r'' not used.
    int k = x->k, l = x->l;

    module256_t *h = DeltaTo(x, offset_h);
    module256_t *z = DeltaTo(x, offset_z);

    assert( k == 4 || k == 6 || k == 8 );
    sigsz = k * 8 + l * 32 * (LOG2_GAMMA1 + 1) + (OMEGA + k);
    if( siglen < sigsz ) return NULL;

    for(i=0; i<k*8; i++)
        x->c_hash[i] = ptr[i];

    for(i=0; i<l; i++)
    {
        Module256DecU(
            ptr + k*8 + i * 32 * (LOG2_GAMMA1 + 1),
            32 * (LOG2_GAMMA1 + 1), z+i, LOG2_GAMMA1+1);

        for(s=0; s<256; s++)
            z[i].r[s] = MLDSA_UModQ(
                ((int64_t)1 << LOG2_GAMMA1) - z[i].r[s]);
    }

    x->status = 0;

    // bogus hint vector.
    if( !HintBitUnpack(
            ptr + k*8 + l * 32 * (LOG2_GAMMA1 + 1),
            k, OMEGA, h) )
    {
        // Error indication from HintBitUnpack is considered
        // part of signature verification failure.
        x->status = -1;
        return NULL;
    }

    // z overflow.
    t = ((int32_t)1 << LOG2_GAMMA1) - BETA;
    for(s=0; s<l; s++)
    {
        if( MLDSA_HasOverflow(z+s, t) )
        {
            x->status = -1;
            return NULL;
        }
    }

    return x;
}

static void const *Dilithium_Verify(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    uint8_t mu[64]); // shared with "internal" routine.

void const *MLDSA_Verify(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen)
{
    uint8_t mu[64];
    shake256_t hctx;
    void *msghash;
    UpdateFunc_t update;

    // returning saved result.
    if( x->status == 1 ) return msg;

    // possible signature decoding failure.
    if( x->status == -1 ) return NULL;

    if( !(msghash = MLDSA_MsgHash_Prelude(
              x->tr, x->ctxstr, x->hfuncs, &update,
              &hctx, DeltaTo(x, offset_hashctx),
              x->hash_oid_tab_ind)) )
        return NULL;

    update(msghash, msg, msglen);

    MLDSA_MsgHash_Postlude(
        mu, x->hashlen, x->hfuncs,
        &hctx, DeltaTo(x, offset_hashctx));

    if( Dilithium_Verify(x, mu) )
        return msg;
    else return NULL;
}

void *MLDSA_IncVerify_Init(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback)
{
    static_assert( sizeof(shake256_t) < sizeof(x->c),
                   "Borrowed object too small" );

    // 2025-01-15:
    // If signature decoder reported error, report it further.
    // Therefore this line is disabled.
    //- x->status = 0;

    return MLDSA_MsgHash_Prelude(
        x->tr, x->ctxstr, x->hfuncs, placeback,
        (void *)&x->c, DeltaTo(x, offset_hashctx),
        x->hash_oid_tab_ind);
}

void *MLDSA_IncVerify_Final(
    MLDSA_Pub_Ctx_Hdr_t *restrict x)
{
    uint8_t mu[64];

    // returning saved result.
    if( x->status == 1 ) return x;

    // possible signature decoding failure.
    if( x->status == -1 ) return NULL;

    MLDSA_MsgHash_Postlude(
        mu, x->hashlen, x->hfuncs,
        (void *)&x->c, DeltaTo(x, offset_hashctx));

    if( Dilithium_Verify(x, mu) )
        return x;
    else return NULL;
}

static void const *Dilithium_Verify( // 2024-08-31: "internal" routine.
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    uint8_t mu[64]) // borrows from "external" routine.
{
    shake_t hctx;
    module256_t *Ahat  = DeltaTo(x, offset_Ahat);
    module256_t *t1hat = DeltaTo(x, offset_t1hat);
    module256_t *z     = DeltaTo(x, offset_z);
    module256_t *h     = DeltaTo(x, offset_h);

    int32_t t;
    int r, s;
    int k = x->k, l = x->l;

    // 2024-08-31: context status check moved to "external" routine.
    //- if( x->status == ... ) return ...;
    //
    // 2025-01-15:
    // tests can pass by grace of there being only 1 invocation of
    // this function in the entire test program.

    // 2024-08-31:
    // The following checks are moved to ``MLDSA_Decode_Signature''.
    // - bogus hint vector.
    // - z overflow.

    // mu := H(tr+M').
    // 2024-08-31: Moved to "external" routine.

    // c := SampleInBall(c_hash).

    SampleInBall(&x->c, x->c_hash, k*8, TAU);
    MLDSA_NTT(&x->c);

    // w  := Az - Tc,
    // w1 := UseHint(w,h),
    // c' := H(mu+w1).

    SHAKE256_Init(&hctx);
    SHAKE_Write(&hctx, mu, 64);

    assert( GAMMA2 == (MLDSA_Q-1)/88 || GAMMA2 == (MLDSA_Q-1)/32 );
    t     = GAMMA2 == (MLDSA_Q-1)/88 ? 6 : 4;
    for(r=0; r<k; r++)
    {
        // t is coeffbits;
        MLDSA_NttScl(&x->w, &x->c, t1hat+r, false);
        for(s=0; s<256; s++)
            x->w.r[s] = MLDSA_UModQ((int64_t)MLDSA_Q - x->w.r[s]);

        for(s=0; s<l; s++)
        {
            if( r == 0 ) // Convert to NTT domain only once initially.
                MLDSA_NTT(z+s);
            MLDSA_NttScl(&x->w, Ahat+r*l+s, z+s, true); // last arg should be true.
        }

        MLDSA_InvNTT(&x->w);

        for(s=0; s<256; s++)
            x->w.r[s] = MLDSA_UseHint(x->w.r[s], h[r].r[s], GAMMA2);

        Module256EncU(x->w1app, t*32, &x->w, t);
        SHAKE_Write(&hctx, x->w1app, t*32);
    }

    assert( k == 4 || k == 6 || k == 8 );
    SHAKE_Final(&hctx);
    SHAKE_Read(&hctx, mu, k*8);

    // c == c'.

    for(s=0; s<k*8; s++)
    {
        if( mu[s] != x->c_hash[s] )
        {
            x->status = -1;
            return NULL;
        }
    }

    x->status = 1;
    return x;
}

void *MLDSA_Verify_Xctrl(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    size_t t;
    (void)flags;

    switch( cmd )
    {
    case MLDSA_set_ctxstr:
        if( !bufvec || veclen < 1 ) return NULL;
        if( bufvec[0].len > 255 ) return NULL;

        x->ctxstr[0] = bufvec[0].len;
        for(t=0; t<bufvec[0].len; t++)
            x->ctxstr[t+1] = ((uint8_t *)bufvec[0].dat)[t];
        return x;
        break;

    default:
        return NULL;
    }
}

#endif /* ! PKC_OMIT_PUB_OPS */

#if ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS)

IntPtr iMLDSA_KeyCodec(int q) { return xMLDSA_KeyCodec(q); }

IntPtr tMLDSA(const CryptoParam_t *P, int q)
{
    return xMLDSA(P[0].aux, P[1].aux, P[2].info, q);
}

IntPtr iMLDSA_CtCodec(int q) { return xMLDSA_CtCodec(q); }

#endif /* ! (PKC_OMIT_KEYGEN || PKC_OMIT_PRIV_OPS || PKC_OMIT_PUB_OPS) */
