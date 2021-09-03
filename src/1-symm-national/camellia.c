/* DannyNiu/NJF, 2021-06-23. Public Domain. */

#include "camellia.h"
#include "../0-datum/endian.h"
#include "../0-datum/sbox.c.h"

static const alignas(256) uint8_t sbox1_table[256] = {
    112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
    35u, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
    134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
    166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
    139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
    223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
    20u,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
    254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
    170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
    16u, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
    135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
    82u, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
    233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
    120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
    114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
    64u,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158,
};

static inline uint64_t func_F(uint64_t X, uint64_t k);
static inline uint64_t func_FL(uint64_t X, uint64_t kl);
static inline uint64_t invf_FL(uint64_t X, uint64_t kl);

static inline uint64_t func_S(uint64_t x);
static inline uint8_t sbox1(uint8_t x);
static inline uint8_t sbox2(uint8_t x);
static inline uint8_t sbox3(uint8_t x);
static inline uint8_t sbox4(uint8_t x);
static inline uint64_t func_P(uint64_t x);

static inline uint64_t func_F(uint64_t X, uint64_t k)
{
    return func_P(func_S(X ^ k));
}

static inline uint64_t func_FL(uint64_t X, uint64_t kl)
{
    uint32_t X_L = X >> 32, X_R = X;
    uint32_t kl_L = kl >> 32, kl_R = kl;
    uint32_t Y_R, Y_L;
    Y_R = X_L & kl_L;
    Y_R = Y_R << 1 | Y_R >> 31;
    Y_R ^= X_R;
    Y_L = Y_R | kl_R;
    Y_L ^= X_L;
    return (uint64_t)Y_L << 32 | Y_R;
}

static inline uint64_t invf_FL(uint64_t Y, uint64_t kl)
{
    uint32_t Y_L = Y >> 32, Y_R = Y;
    uint32_t kl_L = kl >> 32, kl_R = kl;
    uint32_t X_R, X_L;
    X_L = Y_R | kl_R;
    X_L ^= Y_L;
    X_R = X_L & kl_L;
    X_R = X_R << 1 | X_R >> 31;
    X_R ^= Y_R;
    return (uint64_t)X_L << 32 | X_R;
}

static inline uint64_t func_S(uint64_t x)
{
    return
        (uint64_t)sbox1(x >> 56) << 56 |
        (uint64_t)sbox2(x >> 48) << 48 |
        (uint64_t)sbox3(x >> 40) << 40 |
        (uint64_t)sbox4(x >> 32) << 32 |
        (uint64_t)sbox2(x >> 24) << 24 |
        (uint64_t)sbox3(x >> 16) << 16 |
        (uint64_t)sbox4(x >>  8) <<  8 |
        (uint64_t)sbox1(x);
}

static inline uint8_t sbox1(uint8_t x)
{
    return sbox(x, sbox1_table);
}

static inline uint8_t sbox2(uint8_t x)
{
    uint8_t ret = sbox1(x);
    return ret << 1 | ret >> 7;
}

static inline uint8_t sbox3(uint8_t x)
{
    uint8_t ret = sbox1(x);
    return ret >> 1 | ret << 7;
}

static inline uint8_t sbox4(uint8_t x)
{
    x = x << 1 | x >> 7;
    return sbox1(x);
}

static inline uint64_t xmask_bytes(uint64_t x, uint64_t m)
{
    uint64_t ret = x & m;
    ret ^= ret >> 32;
    ret ^= ret >> 16;
    ret ^= ret >>  8;
    return ret & 0xFF;
}

static inline uint64_t func_P(uint64_t x)
{
    return
        xmask_bytes(x, 0xFF00FFFF00FFFFFF) << 56 |
        xmask_bytes(x, 0xFFFF00FFFF00FFFF) << 48 |
        xmask_bytes(x, 0xFFFFFF00FFFF00FF) << 40 |
        xmask_bytes(x, 0x00FFFFFFFFFFFF00) << 32 |
        xmask_bytes(x, 0xFFFF000000FFFFFF) << 24 |
        xmask_bytes(x, 0x00FFFF00FF00FFFF) << 16 |
        xmask_bytes(x, 0x0000FFFFFFFF00FF) <<  8 |
        xmask_bytes(x, 0xFF0000FFFFFFFF00);
}

#define Sigma1 0xA09E667F3BCC908B
#define Sigma2 0xB67AE8584CAA73B2
#define Sigma3 0xC6EF372FE94F82BE
#define Sigma4 0x54FF53A5F1D36F1C
#define Sigma5 0x10E527FADE682D1D
#define Sigma6 0xB05688C2B3E6C1FD

static inline void Camellia_KeySched128( // Left half of the key schedule.
    uint64_t const k[2], // K_L(128) xor (K_R(128) ?? 0)
    uint64_t const k_l[2], // K_L(128)
    camellia128_kschd_t *restrict kw)
{
    uint64_t l, r;
    
    kw->K_LL = be64toh(k_l[0]);
    kw->K_LR = be64toh(k_l[1]);
    l = be64toh(k[0]);
    r = be64toh(k[1]);
    r ^= func_F(l, Sigma1);
    l ^= func_F(r, Sigma2);
    l ^= be64toh(k_l[0]);
    r ^= be64toh(k_l[1]);
    r ^= func_F(l, Sigma3);
    l ^= func_F(r, Sigma4);
    kw->K_AL = l;
    kw->K_AR = r;
}

static inline void Camellia_KeySched256( // The right half.
    uint64_t const k_r[2], // K_R(128)
    camellia256_kschd_t *restrict kw)
{
    uint64_t l, r;

    kw->K_RL = l = be64toh(k_r[0]);
    kw->K_RR = r = be64toh(k_r[1]);
    l ^= kw->K_AL;
    r ^= kw->K_AR;
    r ^= func_F(l, Sigma5);
    l ^= func_F(r, Sigma6);
    kw->K_BL = l;
    kw->K_BR = r;
}

void Camellia128_KeySched(void const *restrict key, void *restrict w)
{
    Camellia_KeySched128(key, key, w);
}

void Camellia192_KeySched(void const *restrict key, void *restrict w)
{
    camellia192_kschd_t *kw = w;
    uint64_t const *k = key;
    uint64_t K128[2];

    K128[0] = k[0] ^ k[2];
    K128[1] = k[1] ^ ~k[2];
    Camellia_KeySched128(K128, k, (camellia128_kschd_t *)kw);

    K128[0] = k[2];
    K128[1] = ~k[2];
    Camellia_KeySched256(K128, kw);
}

void Camellia256_KeySched(void const *restrict key, void *restrict w)
{
    camellia256_kschd_t *kw = w;
    uint64_t const *k = key;
    uint64_t K128[2];

    K128[0] = k[0] ^ k[2];
    K128[1] = k[1] ^ k[3];
    Camellia_KeySched128(K128, k, (camellia128_kschd_t *)kw);

    K128[0] = k[2];
    K128[1] = k[3];
    Camellia_KeySched256(K128, kw);
}

void Camellia128_Encrypt(void const *in, void *out, void const *restrict w)
{
    // Camellia is a horrible cipher. Implementing it is like constipation.
    // So many subroutine primitives, so many exception cases.
    
    const camellia128_kschd_t *kw = w;
    uint64_t l, r;

    l = be64toh( ((const uint64_t *)in)[0] );
    r = be64toh( ((const uint64_t *)in)[1] );

    l ^= kw->K_LL;
    r ^= kw->K_LR;

    r ^= func_F(l, kw->K_AL);
    l ^= func_F(r, kw->K_AR);
    r ^= func_F(l, kw->K_LL << 15 | kw->K_LR >> 49);
    l ^= func_F(r, kw->K_LR << 15 | kw->K_LL >> 49);
    r ^= func_F(l, kw->K_AL << 15 | kw->K_AR >> 49);
    l ^= func_F(r, kw->K_AR << 15 | kw->K_AL >> 49);

    l = func_FL(l, kw->K_AL << 30 | kw->K_AR >> 34);
    r = invf_FL(r, kw->K_AR << 30 | kw->K_AL >> 34);
    
    r ^= func_F(l, kw->K_LL << 45 | kw->K_LR >> 19);
    l ^= func_F(r, kw->K_LR << 45 | kw->K_LL >> 19);
    r ^= func_F(l, kw->K_AL << 45 | kw->K_AR >> 19);
    l ^= func_F(r, kw->K_LR << 60 | kw->K_LL >>  4);
    r ^= func_F(l, kw->K_AL << 60 | kw->K_AR >>  4);
    l ^= func_F(r, kw->K_AR << 60 | kw->K_AL >>  4);

    l = func_FL(l, kw->K_LR << 13 | kw->K_LL >> 51); // 13 = 77 - 64.
    r = invf_FL(r, kw->K_LL << 13 | kw->K_LR >> 51);
    
    r ^= func_F(l, kw->K_LR << 30 | kw->K_LL >> 34); // 30 = 94 - 64.
    l ^= func_F(r, kw->K_LL << 30 | kw->K_LR >> 34);
    r ^= func_F(l, kw->K_AR << 30 | kw->K_AL >> 34); 
    l ^= func_F(r, kw->K_AL << 30 | kw->K_AR >> 34);
    r ^= func_F(l, kw->K_LR << 47 | kw->K_LL >> 17); // 47 = 111 - 64.
    l ^= func_F(r, kw->K_LL << 47 | kw->K_LR >> 17);

    r ^= kw->K_AR << 47 | kw->K_AL >> 17;
    l ^= kw->K_AL << 47 | kw->K_AR >> 17;

    ((uint64_t *)out)[0] = htobe64(r);
    ((uint64_t *)out)[1] = htobe64(l);
}

void Camellia128_Decrypt(void const *in, void *out, void const *restrict w)
{
    const camellia128_kschd_t *kw = w;
    uint64_t l, r;

    l = be64toh( ((const uint64_t *)in)[1] );
    r = be64toh( ((const uint64_t *)in)[0] );

    l ^= kw->K_AL << 47 | kw->K_AR >> 17;
    r ^= kw->K_AR << 47 | kw->K_AL >> 17;
    
    l ^= func_F(r, kw->K_LL << 47 | kw->K_LR >> 17);
    r ^= func_F(l, kw->K_LR << 47 | kw->K_LL >> 17); // 47 = 111 - 64.
    l ^= func_F(r, kw->K_AL << 30 | kw->K_AR >> 34);
    r ^= func_F(l, kw->K_AR << 30 | kw->K_AL >> 34); 
    l ^= func_F(r, kw->K_LL << 30 | kw->K_LR >> 34);
    r ^= func_F(l, kw->K_LR << 30 | kw->K_LL >> 34); // 30 = 94 - 64.

    r = func_FL(r, kw->K_LL << 13 | kw->K_LR >> 51);
    l = invf_FL(l, kw->K_LR << 13 | kw->K_LL >> 51); // 13 = 77 - 64.
    
    l ^= func_F(r, kw->K_AR << 60 | kw->K_AL >>  4);
    r ^= func_F(l, kw->K_AL << 60 | kw->K_AR >>  4);
    l ^= func_F(r, kw->K_LR << 60 | kw->K_LL >>  4);
    r ^= func_F(l, kw->K_AL << 45 | kw->K_AR >> 19);
    l ^= func_F(r, kw->K_LR << 45 | kw->K_LL >> 19);
    r ^= func_F(l, kw->K_LL << 45 | kw->K_LR >> 19);

    r = func_FL(r, kw->K_AR << 30 | kw->K_AL >> 34);
    l = invf_FL(l, kw->K_AL << 30 | kw->K_AR >> 34);

    l ^= func_F(r, kw->K_AR << 15 | kw->K_AL >> 49);
    r ^= func_F(l, kw->K_AL << 15 | kw->K_AR >> 49);
    l ^= func_F(r, kw->K_LR << 15 | kw->K_LL >> 49);
    r ^= func_F(l, kw->K_LL << 15 | kw->K_LR >> 49);
    l ^= func_F(r, kw->K_AR);
    r ^= func_F(l, kw->K_AL);

    r ^= kw->K_LR;
    l ^= kw->K_LL;

    ((uint64_t *)out)[0] = htobe64(l);
    ((uint64_t *)out)[1] = htobe64(r);
}

void Camellia256_Encrypt(void const *in, void *out, void const *restrict w)
{
    const camellia256_kschd_t *kw = w;
    uint64_t l, r;

    l = be64toh( ((const uint64_t *)in)[0] );
    r = be64toh( ((const uint64_t *)in)[1] );

    l ^= kw->K_LL;
    r ^= kw->K_LR;

    r ^= func_F(l, kw->K_BL);
    l ^= func_F(r, kw->K_BR);
    r ^= func_F(l, kw->K_RL << 15 | kw->K_RR >> 49);
    l ^= func_F(r, kw->K_RR << 15 | kw->K_RL >> 49);
    r ^= func_F(l, kw->K_AL << 15 | kw->K_AR >> 49);
    l ^= func_F(r, kw->K_AR << 15 | kw->K_AL >> 49);

    l = func_FL(l, kw->K_RL << 30 | kw->K_RR >> 34);
    r = invf_FL(r, kw->K_RR << 30 | kw->K_RL >> 34);
    
    r ^= func_F(l, kw->K_BL << 30 | kw->K_BR >> 34);
    l ^= func_F(r, kw->K_BR << 30 | kw->K_BL >> 34);
    r ^= func_F(l, kw->K_LL << 45 | kw->K_LR >> 19);
    l ^= func_F(r, kw->K_LR << 45 | kw->K_LL >> 19);
    r ^= func_F(l, kw->K_AL << 45 | kw->K_AR >> 19);
    l ^= func_F(r, kw->K_AR << 45 | kw->K_AL >> 19);

    l = func_FL(l, kw->K_LL << 60 | kw->K_LR >>  4);
    r = invf_FL(r, kw->K_LR << 60 | kw->K_LL >>  4);
    
    r ^= func_F(l, kw->K_RL << 60 | kw->K_RR >>  4);
    l ^= func_F(r, kw->K_RR << 60 | kw->K_RL >>  4);
    r ^= func_F(l, kw->K_BL << 60 | kw->K_BR >>  4);
    l ^= func_F(r, kw->K_BR << 60 | kw->K_BL >>  4);
    r ^= func_F(l, kw->K_LR << 13 | kw->K_LL >> 51); // 13 = 77 - 64.
    l ^= func_F(r, kw->K_LL << 13 | kw->K_LR >> 51);

    l = func_FL(l, kw->K_AR << 13 | kw->K_AL >> 51);
    r = invf_FL(r, kw->K_AL << 13 | kw->K_AR >> 51);

    r ^= func_F(l, kw->K_RR << 30 | kw->K_RL >> 34); // 30 = 94 - 64.
    l ^= func_F(r, kw->K_RL << 30 | kw->K_RR >> 34);
    r ^= func_F(l, kw->K_AR << 30 | kw->K_AL >> 34);
    l ^= func_F(r, kw->K_AL << 30 | kw->K_AR >> 34);
    r ^= func_F(l, kw->K_LR << 47 | kw->K_LL >> 17); // 47 = 111 - 64.
    l ^= func_F(r, kw->K_LL << 47 | kw->K_LR >> 17);

    r ^= kw->K_BR << 47 | kw->K_BL >> 17;
    l ^= kw->K_BL << 47 | kw->K_BR >> 17;

    ((uint64_t *)out)[0] = htobe64(r);
    ((uint64_t *)out)[1] = htobe64(l);
}

void Camellia256_Decrypt(void const *in, void *out, void const *restrict w)
{
    const camellia256_kschd_t *kw = w;
    uint64_t l, r;

    l = be64toh( ((const uint64_t *)in)[1] );
    r = be64toh( ((const uint64_t *)in)[0] );

    l ^= kw->K_BL << 47 | kw->K_BR >> 17;
    r ^= kw->K_BR << 47 | kw->K_BL >> 17;

    l ^= func_F(r, kw->K_LL << 47 | kw->K_LR >> 17);
    r ^= func_F(l, kw->K_LR << 47 | kw->K_LL >> 17); // 47 = 111 - 64.
    l ^= func_F(r, kw->K_AL << 30 | kw->K_AR >> 34);
    r ^= func_F(l, kw->K_AR << 30 | kw->K_AL >> 34);
    l ^= func_F(r, kw->K_RL << 30 | kw->K_RR >> 34);
    r ^= func_F(l, kw->K_RR << 30 | kw->K_RL >> 34); // 30 = 94 - 64.

    r = func_FL(r, kw->K_AL << 13 | kw->K_AR >> 51);
    l = invf_FL(l, kw->K_AR << 13 | kw->K_AL >> 51);
    
    l ^= func_F(r, kw->K_LL << 13 | kw->K_LR >> 51);
    r ^= func_F(l, kw->K_LR << 13 | kw->K_LL >> 51); // 13 = 77 - 64.
    l ^= func_F(r, kw->K_BR << 60 | kw->K_BL >>  4);
    r ^= func_F(l, kw->K_BL << 60 | kw->K_BR >>  4);
    l ^= func_F(r, kw->K_RR << 60 | kw->K_RL >>  4);
    r ^= func_F(l, kw->K_RL << 60 | kw->K_RR >>  4);

    r = func_FL(r, kw->K_LR << 60 | kw->K_LL >>  4);
    l = invf_FL(l, kw->K_LL << 60 | kw->K_LR >>  4);
    
    l ^= func_F(r, kw->K_AR << 45 | kw->K_AL >> 19);
    r ^= func_F(l, kw->K_AL << 45 | kw->K_AR >> 19);
    l ^= func_F(r, kw->K_LR << 45 | kw->K_LL >> 19);
    r ^= func_F(l, kw->K_LL << 45 | kw->K_LR >> 19);
    l ^= func_F(r, kw->K_BR << 30 | kw->K_BL >> 34);
    r ^= func_F(l, kw->K_BL << 30 | kw->K_BR >> 34);

    r = func_FL(r, kw->K_RR << 30 | kw->K_RL >> 34);
    l = invf_FL(l, kw->K_RL << 30 | kw->K_RR >> 34);

    l ^= func_F(r, kw->K_AR << 15 | kw->K_AL >> 49);
    r ^= func_F(l, kw->K_AL << 15 | kw->K_AR >> 49);
    l ^= func_F(r, kw->K_RR << 15 | kw->K_RL >> 49);
    r ^= func_F(l, kw->K_RL << 15 | kw->K_RR >> 49);
    l ^= func_F(r, kw->K_BR);
    r ^= func_F(l, kw->K_BL);

    r ^= kw->K_LR;
    l ^= kw->K_LL;

    ((uint64_t *)out)[0] = htobe64(l);
    ((uint64_t *)out)[1] = htobe64(r);
}

IntPtr iCamellia128(int q) { return xCamellia128(q); }
IntPtr iCamellia192(int q) { return xCamellia192(q); }
IntPtr iCamellia256(int q) { return xCamellia256(q); }
