/* DannyNiu/NJF, 2020-11-28. Public Domain. */

#include "ctr-drbg.h"
#include "../0-exec/struct-delta.c.h"

static void inc(uint8_t *vec)
{
    int16_t a = 1, i = 0;
    while( i++ < 4 )
    {
        vec[-i] = (a += vec[-i]);
        a >>= 8;
    }
}

#define KSCHD_PTR ((void *)((uint8_t *)x + x->kschd_offset))

static void CTR_DRBG_Update(
    ctr_drbg_t *restrict x,
    void const *restrict str,
    size_t len)
{
    uint8_t blk[CTR_DRBG_MAX_BLKSIZE];
    uint8_t *seed = DeltaTo(x, offset_k);
    size_t t;

    // 2022-05-23:
    // assert for block size, added to make linter more accurate.
    assert( x->bc_blksize >= 8 ); // 16 actually.

    // Copy V to blk.
    for(t = 0; t<x->bc_blksize; t++)
        blk[t] = *(seed + x->bc_keysize + t);

    // condition is the simplified form of: b + k >= t + b
    for(t = 0; t <= x->bc_keysize; t += x->bc_blksize)
    {
        inc(blk + x->bc_blksize); // ctr_len == 32 in bits.
        x->bc_enc(blk, seed + t, KSCHD_PTR);
    }

    if( x->bc_blksize + x->bc_keysize > t )
    {
        size_t o = 0;
        inc(blk + x->bc_blksize);
        x->bc_enc(blk, blk, KSCHD_PTR);
        while( t < x->bc_keysize + x->bc_blksize )
            seed[t++] = blk[o++];
    }

    // mix with provided data.
    if( str )
    {
        for(t = 0; t < len && t < x->bc_blksize + x->bc_keysize; t++)
            seed[t] ^= ((uint8_t const *)str)[t];
    }

    // update key schedule.
    x->bc_kschd(seed, KSCHD_PTR);

    // 2021-09-12:
    // This function CTR_DRBG_Update had been verified as correct
    // manually against "CTR_DRBG_withDF.pdf" section:
    // CTR_DRBG_AES128 >> Prediction_Resistance >>
    // CTR_DRBG_Generate >> CTR_DRBG_Reseed >> Update.
}

void CTR_DRBG_Seed(
    ctr_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len)
{
    uint8_t *seed = DeltaTo(x, offset_k);
    size_t t;

    // 2022-05-23:
    // assert for block and key sizes, added to make linter more accurate.
    assert( x->bc_blksize >= 8 && x->bc_blksize <= CTR_DRBG_MAX_BLKSIZE );
    assert( x->bc_keysize >= 8 && x->bc_keysize <= CTR_DRBG_MAX_KEYSIZE );

    for(t = 0; t < x->bc_blksize + x->bc_keysize; t++)
        seed[t] = 0;

    x->bc_kschd(seed, KSCHD_PTR);
    CTR_DRBG_Update(x, seedstr, len);
}

void CTR_DRBG_Reseed(
    ctr_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len)
{
    CTR_DRBG_Update(x, seedstr, len);
}

void CTR_DRBG_Generate(
    ctr_drbg_t *restrict x,
    void *restrict out,
    size_t len)
{
    uint8_t blk[CTR_DRBG_MAX_BLKSIZE];
    uint8_t *seed = DeltaTo(x, offset_k);
    uint8_t *buf = out;
    size_t t;

    // 2022-05-23:
    // assert for block size, added to make linter more accurate.
    assert( x->bc_blksize >= 8 ); // 16 actually.

    // Copy V to blk.
    for(t = 0; t < x->bc_blksize; t++)
        blk[t] = *(seed + x->bc_keysize + t);

    // slightly modified based on CTR_DRBG_Instantiate.
    for(t = 0; t + x->bc_blksize <= len; t += x->bc_blksize)
    {
        inc(blk + x->bc_blksize); // ctr_len == 32 in bits.
        x->bc_enc(blk, buf + t, KSCHD_PTR);
    }

    if( t < len )
    {
        size_t o = 0;
        inc(blk + x->bc_blksize);
        x->bc_enc(blk, blk, KSCHD_PTR);
        while( t < len )
            buf[t++] = blk[o++];
    }

    CTR_DRBG_Update(x, NULL, 0); // additional input is unsupported.
}

#if ! CTR_DRBG_OMIT_DF

static void BCC(
    ctr_drbg_t *restrict x,
    size_t n,
    bufvec_t *restrict bufelems,
    void *restrict outblk)
{
    uint8_t *buf = outblk;
    size_t t, o;

    for(t=0; t<x->bc_blksize; t++) buf[t] = 0;

    for(t=o=0; n; o=0, bufelems++, n--)
    {
        while( t < x->bc_blksize && o < bufelems->len )
        {
            buf[t++] ^= ((const uint8_t *)bufelems->buf)[o++];

            if( t >= x->bc_blksize )
            {
                t = 0;
                x->bc_enc(buf, buf, KSCHD_PTR);
            }
        }
    }

    buf[t++] ^= 0x80;
    x->bc_enc(buf, buf, KSCHD_PTR);

    // 2021-09-12:
    // This function BCC had been verified as correct
    // manually against "CTR_DRBG_withDF.pdf" section:
    // CTR_DRBG_AES128 >> Prediction_Resistance >>
    // CTR_DRBG_Instantiate_algorithm.
}

static void BlockCipher_df(
    ctr_drbg_t *restrict x,
    void const *restrict in, size_t inlen,
    void      *restrict out, size_t outlen)
{
    uint8_t LN[8]; // Variables L and N, 32-bits each.
    uint8_t buf[CTR_DRBG_MAX_BLKSIZE];
    uint8_t tmp[CTR_DRBG_MAX_BLKSIZE];

    uint8_t key[CTR_DRBG_MAX_KEYSIZE + CTR_DRBG_MAX_BLKSIZE];
    uint8_t *blk = key + x->bc_keysize;

    bufvec_t bufvec[3];

    size_t t, o;

    // set lengths prefix.
    for(o = 0; o < 4; o++)
    {
        LN[o + 0] =  inlen >> (24 - o * 8);
        LN[o + 4] = outlen >> (24 - o * 8);
    }

    // initialize stub key.
    for(o = 0; o < x->bc_keysize; o++) key[o] = o;
    x->bc_kschd(key, KSCHD_PTR);

    // set the variable - IV.
    for(o = 0; o < x->bc_blksize; o++) buf[o] = 0;

    // set buffers vector.
    bufvec[0].len = x->bc_blksize;
    bufvec[0].dat = buf;
    bufvec[1].len = sizeof(LN);
    bufvec[1].dat = LN;
    bufvec[2].len = inlen;
    bufvec[2].dat = in;

    // condition is the simplified form of: b + k >= t + b
    for(t = 0; t <= x->bc_keysize; t += x->bc_blksize)
    {
        BCC(x, 3, bufvec, tmp);
        for(o = 0; o < x->bc_blksize; o++)
        {
            if( o + t < x->bc_keysize + x->bc_blksize )
                key[t + o] = tmp[o];
            else break;
        }

        // increment.
        inc(buf + 4); // ctr_len == 32 in bits.
    }

    // 2021-09-13:
    // the absence of this if block caused CTR-DRBG-AES192 to fail.
    if( x->bc_keysize + x->bc_blksize > t )
    {
        BCC(x, 3, bufvec, tmp);
        for(o = 0; o < x->bc_blksize; o++)
        {
            if( o + t < x->bc_keysize + x->bc_blksize )
                key[t + o] = tmp[o];
            else break;
        }
    }


    // set new K.
    x->bc_kschd(key, KSCHD_PTR);

    // iterate over X using K.
    for(t = 0; t < outlen; t += x->bc_blksize)
    {
        x->bc_enc(blk, blk, KSCHD_PTR);
        for(o = 0; o < x->bc_blksize; o++)
        {
            if( o + t < outlen )
                ((uint8_t *)out)[t + o] = blk[o];
            else break;
        }
    }

    // 2021-09-12:
    // This function BlockCipher_df had been verified as correct
    // manually against "CTR_DRBG_withDF.pdf" section:
    // CTR_DRBG_AES128 >> Prediction_Resistance >>
    // CTR_DRBG_Instantiate_algorithm.
}

void CTR_DRBG_Seed_WithDF(
    ctr_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len)
{
    uint8_t seed_material[CTR_DRBG_MAX_KEYSIZE + CTR_DRBG_MAX_BLKSIZE];
    size_t seedlen = x->bc_blksize + x->bc_keysize;

    BlockCipher_df(x, seedstr, len, seed_material, seedlen);

    CTR_DRBG_Seed(x, seed_material, seedlen);
}

void CTR_DRBG_Reseed_WithDF(
    ctr_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len)
{
    uint8_t seed_material[CTR_DRBG_MAX_KEYSIZE + CTR_DRBG_MAX_BLKSIZE];
    size_t seedlen = x->bc_blksize + x->bc_keysize;

    BlockCipher_df(x, seedstr, len, seed_material, seedlen);

    // 2021-09-11:
    // forgetting to reset key schedule was a cause of inconsistency.
    x->bc_kschd(DeltaTo(x, offset_k), KSCHD_PTR);

    CTR_DRBG_Update(x, seed_material, seedlen);
}

#endif /* ! CTR_DRBG_OMIT_DF */

#ifndef __CTR_DRBG_Seed
#include "ctr-drbg.c.h" // Included only to use ``__CTR_DRBG_Seed''
#endif

#define cT(q) (P->param ? P->proto(P->param, q) : P->info(q))

IntPtr tCTR_DRBG(const CryptoParam_t *P, int q) { return xCTR_DRBG(T,q); }

void *CTR_DRBG_T_InstInit(
    const CryptoParam_t *restrict P,
    ctr_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len)
{
    assert(P); // 2022-05-23: assertion added to make linter more accurate.
    *x = CTR_DRBG_INIT(cT);

    if( x->bc_blksize > CTR_DRBG_MAX_BLKSIZE ||
        x->bc_keysize > CTR_DRBG_MAX_KEYSIZE )
        return NULL;

    if( x->bc_blksize < 8 || x->bc_keysize < 8 )
        return NULL;

    __CTR_DRBG_Seed(x, seedstr, len);
    return x;
}
