/* DannyNiu/NJF, 2021-07-19. Public Domain. */

#include "aria.h"
#include "../0-datum/endian.h"
#include "../0-datum/sbox.c.h"

static const alignas(256) uint8_t table_SB1[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const alignas(256) uint8_t table_SB2[256] = {
    0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
    0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
    0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
    0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
    0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
    0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
    0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
    0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
    0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
    0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
    0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
    0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
    0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
    0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
    0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
    0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81,
};

static inline uint8_t SB1(uint8_t x)
{
    return sbox(x, table_SB1);
}

static inline uint8_t SB2(uint8_t x)
{
    return sbox(x, table_SB2);
}

static inline uint8_t SB3(uint8_t x)
{
    return invsbox(x, table_SB1);
}

static inline uint8_t SB4(uint8_t x)
{
    return invsbox(x, table_SB2);
}

static void SL1(uint8_t x[16])
{
    uint8_t y[16];
    int i;

    for(i=0; i<4; i++)
    {
        y[i * 4 + 0] = SB1(x[i * 4 + 0]);
        y[i * 4 + 1] = SB2(x[i * 4 + 1]);
        y[i * 4 + 2] = SB3(x[i * 4 + 2]);
        y[i * 4 + 3] = SB4(x[i * 4 + 3]);
    }

    for(i=0; i<16; i++) x[i] = y[i];
}

static void SL2(uint8_t x[16])
{
    uint8_t y[16];
    int i;

    for(i=0; i<4; i++)
    {
        y[i * 4 + 0] = SB3(x[i * 4 + 0]);
        y[i * 4 + 1] = SB4(x[i * 4 + 1]);
        y[i * 4 + 2] = SB1(x[i * 4 + 2]);
        y[i * 4 + 3] = SB2(x[i * 4 + 3]);
    }

    for(i=0; i<16; i++) x[i] = y[i];
}

static void A(uint8_t x[16])
{
    uint8_t y[16];
    int i;
    
    y[0]  = x[3] ^ x[4] ^ x[6] ^ x[8]  ^ x[9]  ^ x[13] ^ x[14];
    y[1]  = x[2] ^ x[5] ^ x[7] ^ x[8]  ^ x[9]  ^ x[12] ^ x[15];
    y[2]  = x[1] ^ x[4] ^ x[6] ^ x[10] ^ x[11] ^ x[12] ^ x[15];
    y[3]  = x[0] ^ x[5] ^ x[7] ^ x[10] ^ x[11] ^ x[13] ^ x[14];
    y[4]  = x[0] ^ x[2] ^ x[5] ^ x[8]  ^ x[11] ^ x[14] ^ x[15];
    y[5]  = x[1] ^ x[3] ^ x[4] ^ x[9]  ^ x[10] ^ x[14] ^ x[15];
    y[6]  = x[0] ^ x[2] ^ x[7] ^ x[9]  ^ x[10] ^ x[12] ^ x[13];
    y[7]  = x[1] ^ x[3] ^ x[6] ^ x[8]  ^ x[11] ^ x[12] ^ x[13];

    y[8]  = x[0] ^ x[1] ^ x[4] ^ x[7]  ^ x[10] ^ x[13] ^ x[15];
    y[9]  = x[0] ^ x[1] ^ x[5] ^ x[6]  ^ x[11] ^ x[12] ^ x[14];
    y[10] = x[2] ^ x[3] ^ x[5] ^ x[6]  ^ x[8]  ^ x[13] ^ x[15];
    y[11] = x[2] ^ x[3] ^ x[4] ^ x[7]  ^ x[9]  ^ x[12] ^ x[14];
    y[12] = x[1] ^ x[2] ^ x[6] ^ x[7]  ^ x[9]  ^ x[11] ^ x[12];
    y[13] = x[0] ^ x[3] ^ x[6] ^ x[7]  ^ x[8]  ^ x[10] ^ x[13];
    y[14] = x[0] ^ x[3] ^ x[4] ^ x[5]  ^ x[9]  ^ x[11] ^ x[14];
    y[15] = x[1] ^ x[2] ^ x[4] ^ x[5]  ^ x[8]  ^ x[10] ^ x[15];

    for(i=0; i<16; i++) x[i] = y[i];
}

static void FO(uint8_t *restrict D, uint8_t const *restrict RK)
{
    int i;
    
    if( RK ) for(i=0; i<16; i++) D[i] ^= RK[i];
    SL1(D);
    A(D);
}

static void FE(uint8_t *restrict D, uint8_t const *restrict RK)
{
    int i;
    
    if( RK ) for(i=0; i<16; i++) D[i] ^= RK[i];
    SL2(D);
    A(D);
}

static void ARIA_Kschd_Generic(
    uint64_t *ek, int c, // ``c'' must be one of 12, 14, 16.
    uint64_t W0h, uint64_t W0l,
    uint64_t W1h, uint64_t W1l,
    uint64_t W2h, uint64_t W2l,
    uint64_t W3h, uint64_t W3l)
{
    //
    // higher 64-bit half
    
    ek[ 0] = W0h ^ (W1h >> 19 | W1l << 45);
    ek[ 2] = W1h ^ (W2h >> 19 | W2l << 45);
    ek[ 4] = W2h ^ (W3h >> 19 | W3l << 45);
    ek[ 6] = W3h ^ (W0h >> 19 | W0l << 45);
    
    ek[ 8] = W0h ^ (W1h >> 31 | W1l << 33);
    ek[10] = W1h ^ (W2h >> 31 | W2l << 33);
    ek[12] = W2h ^ (W3h >> 31 | W3l << 33);
    ek[14] = W3h ^ (W0h >> 31 | W0l << 33);
    
    ek[16] = W0h ^ (W1h << 61 | W1l >>  3);
    ek[18] = W1h ^ (W2h << 61 | W2l >>  3);
    ek[20] = W2h ^ (W3h << 61 | W3l >>  3);
    ek[22] = W3h ^ (W0h << 61 | W0l >>  3);
    
    ek[24] = W0h ^ (W1h << 31 | W1l >> 33);
    if( c > 12 )
    {
        ek[26] = W1h ^ (W2h << 31 | W2l >> 33);
        ek[28] = W2h ^ (W3h << 31 | W3l >> 33);
        if( c > 14 )
        {
            ek[30] = W3h ^ (W0h << 31 | W0l >> 33);
    
            ek[32] = W0h ^ (W1h << 19 | W1l >> 45);
        }
    }

    //
    // lower 64-bit half
    
    ek[ 1] = W0l ^ (W1l >> 19 | W1h << 45);
    ek[ 3] = W1l ^ (W2l >> 19 | W2h << 45);
    ek[ 5] = W2l ^ (W3l >> 19 | W3h << 45);
    ek[ 7] = W3l ^ (W0l >> 19 | W0h << 45);
    
    ek[ 9] = W0l ^ (W1l >> 31 | W1h << 33);
    ek[11] = W1l ^ (W2l >> 31 | W2h << 33);
    ek[13] = W2l ^ (W3l >> 31 | W3h << 33);
    ek[15] = W3l ^ (W0l >> 31 | W0h << 33);
    
    ek[17] = W0l ^ (W1l << 61 | W1h >>  3);
    ek[19] = W1l ^ (W2l << 61 | W2h >>  3);
    ek[21] = W2l ^ (W3l << 61 | W3h >>  3);
    ek[23] = W3l ^ (W0l << 61 | W0h >>  3);
    
    ek[25] = W0l ^ (W1l << 31 | W1h >> 33);
    if( c > 12 )
    {
        ek[27] = W1l ^ (W2l << 31 | W2h >> 33);
        ek[29] = W2l ^ (W3l << 31 | W3h >> 33);
        if( c > 14 )
        {
            ek[31] = W3l ^ (W0l << 31 | W0h >> 33);
            
            ek[33] = W0l ^ (W1l << 19 | W1h >> 45);
        }
    }

    //
    // restore endianness.
    
    c = (c + 1) * 2;
    while( c-- > 0 ) ek[c] = htobe64(ek[c]);
}

static const uint64_t C1h = 0x517cc1b727220a94;
static const uint64_t C1l = 0xfe13abe8fa9a6ee0;
static const uint64_t C2h = 0x6db14acc9e21c820;
static const uint64_t C2l = 0xff28b1d5ef5de2b0;
static const uint64_t C3h = 0xdb92371d2126e970;
static const uint64_t C3l = 0x0324977504e8c90e;

void ARIA128_KeySched(void const *restrict k, void *restrict w)
{
    uint64_t const *key = k;
    uint64_t W[8];
    int i;

    W[0] = key[0];
    W[1] = key[1];

    W[2] = W[0] ^ htobe64(C1h);
    W[3] = W[1] ^ htobe64(C1l);
    FO((void *)(W + 2), NULL);
    // W[2] ^= 0;
    // W[3] ^= 0;

    W[4] = W[2] ^ htobe64(C2h);
    W[5] = W[3] ^ htobe64(C2l);
    FE((void *)(W + 4), NULL);
    W[4] ^= W[0];
    W[5] ^= W[1];

    W[6] = W[4] ^ htobe64(C3h);
    W[7] = W[5] ^ htobe64(C3l);
    FO((void *)(W + 6), NULL);
    W[6] ^= W[2];
    W[7] ^= W[3];

    for(i=0; i<8; i++) W[i] = be64toh(W[i]);
    ARIA_Kschd_Generic(
        w, 12,
        W[0], W[1], W[2], W[3],
        W[4], W[5], W[6], W[7]);
}

void ARIA192_KeySched(void const *restrict k, void *restrict w)
{
    uint64_t const *key = k;
    uint64_t W[8];
    int i;

    W[0] = key[0];
    W[1] = key[1];

    W[2] = W[0] ^ htobe64(C2h);
    W[3] = W[1] ^ htobe64(C2l);
    FO((void *)(W + 2), NULL);
    W[2] ^= key[2];
    // W[3] ^= 0;

    W[4] = W[2] ^ htobe64(C3h);
    W[5] = W[3] ^ htobe64(C3l);
    FE((void *)(W + 4), NULL);
    W[4] ^= W[0];
    W[5] ^= W[1];

    W[6] = W[4] ^ htobe64(C1h);
    W[7] = W[5] ^ htobe64(C1l);
    FO((void *)(W + 6), NULL);
    W[6] ^= W[2];
    W[7] ^= W[3];

    for(i=0; i<8; i++) W[i] = be64toh(W[i]);
    ARIA_Kschd_Generic(
        w, 14,
        W[0], W[1], W[2], W[3],
        W[4], W[5], W[6], W[7]);
}

void ARIA256_KeySched(void const *restrict k, void *restrict w)
{
    uint64_t const *key = k;
    uint64_t W[8];
    int i;

    W[0] = key[0];
    W[1] = key[1];

    W[2] = W[0] ^ htobe64(C3h);
    W[3] = W[1] ^ htobe64(C3l);
    FO((void *)(W + 2), NULL);
    W[2] ^= key[2];
    W[3] ^= key[3];

    W[4] = W[2] ^ htobe64(C1h);
    W[5] = W[3] ^ htobe64(C1l);
    FE((void *)(W + 4), NULL);
    W[4] ^= W[0];
    W[5] ^= W[1];

    W[6] = W[4] ^ htobe64(C2h);
    W[7] = W[5] ^ htobe64(C2l);
    FO((void *)(W + 6), NULL);
    W[6] ^= W[2];
    W[7] ^= W[3];

    for(i=0; i<8; i++) W[i] = be64toh(W[i]);
    ARIA_Kschd_Generic(
        w, 16,
        W[0], W[1], W[2], W[3],
        W[4], W[5], W[6], W[7]);
}

static void ARIA_Encrypt_Generic(
    uint8_t const in[16], uint8_t out[16],
    uint8_t const *ek, int c) // ``c'' must bne one of 12, 14, 16.
{
    int i;

    for(i=0; i<16; i++) out[i] = in[i];

    for(i=0, c=c/2-1; i<c; i++)
    {
        FO(out, &ek[(i * 2 + 0) * 16]);
        FE(out, &ek[(i * 2 + 1) * 16]);
    }

    FO(out, &ek[(i * 2 + 0) * 16]);
    
    for(c=0; c<16; c++) out[c] ^= ek[(i * 2 + 1) * 16 + c];

    SL2(out);

    for(c=0; c<16; c++) out[c] ^= ek[(i * 2 + 2) * 16 + c];
}

static void ARIA_Decrypt_Generic(
    uint8_t const in[16], uint8_t out[16],
    uint8_t const *ek, int c) // ``c'' must bne one of 12, 14, 16.
{
    // As newer blockcipher modes are mostly CTR-based AEADs, I decided to
    // deprioritize the efficient implementation of ARIA decryption.
    
    uint8_t dk[16];
    int i;

    for(i=0; i<16; i++)
    {
        out[i] = in[i];
        dk[i] = ek[c * 16 + i];
    }

    for(i=c; i>2; )
    {
        FO(out, dk);
        for(c=0, i--; c<16; c++) dk[c] = ek[i * 16 + c];
        A(dk);
        
        FE(out, dk);
        for(c=0, i--; c<16; c++) dk[c] = ek[i * 16 + c];
        A(dk);
    }

    FO(out, dk);
    for(c=0, i--; c<16; c++) dk[c] = ek[1 * 16 + c];
    A(dk);
    
    for(c=0; c<16; c++) out[c] ^= dk[c];

    SL2(out);

    for(c=0; c<16; c++) out[c] ^= ek[0 * 16 + c];
}

void ARIA128_Encrypt(void const *in, void *out, void const *restrict w)
{
    return ARIA_Encrypt_Generic(in, out, w, 12);
}

void ARIA192_Encrypt(void const *in, void *out, void const *restrict w)
{
    return ARIA_Encrypt_Generic(in, out, w, 14);
}

void ARIA256_Encrypt(void const *in, void *out, void const *restrict w)
{
    return ARIA_Encrypt_Generic(in, out, w, 16);
}

void ARIA128_Decrypt(void const *in, void *out, void const *restrict w)
{
    return ARIA_Decrypt_Generic(in, out, w, 12);
}

void ARIA192_Decrypt(void const *in, void *out, void const *restrict w)
{
    return ARIA_Decrypt_Generic(in, out, w, 14);
}

void ARIA256_Decrypt(void const *in, void *out, void const *restrict w)
{
    return ARIA_Decrypt_Generic(in, out, w, 16);
}

IntPtr iARIA128(int q){ return xARIA128(q); }
IntPtr iARIA192(int q){ return xARIA192(q); }
IntPtr iARIA256(int q){ return xARIA256(q); }
