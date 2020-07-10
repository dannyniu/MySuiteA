/* DannyNiu/NJF, 2018-02-05. Public Domain. */

#include "fips-180.h"
#include "../0-datum/endian.h"

#define Ch(x,y,z) ((x&y)^((~x)&z))
#define Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define Parity(x,y,z) (x^y^z)

#define ROTL(x,n) (( (x)<<(n) )|( (x)>>(32-(n)) ))
#define ROTR(x,n) (( (x)>>(n) )|( (x)<<(32-(n)) ))

#define K_sha1(t) (\
    t<20 ? 0x5a827999 : \
    t<40 ? 0x6ed9eba1 : \
    t<60 ? 0x8f1bbcdc : 0xca62c1d6 )

void compressfunc_sha1(uint32_t H[5], uint32_t const *restrict M)
{
    // Working Variables. 
    uint32_t a, b, c, d, e, T, W[16];
    int t;

    for(t=0; t<16; t++) W[t] = be32toh(M[t]);
    // Initializing Working Variables.

    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];

    // Applying Message Schedule.
    
    for(t=0; t<80; t++) {
        T = ROTL(a,5) + (
            t < 20 ? Ch(b,c,d) :
            t < 40 ? Parity(b,c,d) :
            t < 60 ? Maj(b,c,d) : Parity(b,c,d)
            ) + e + K_sha1(t) +
            ( t<16 ? W[t] :
              ( W[t%16] =
                ROTL(W[(t-3)%16]^
                     W[(t-8)%16]^
                     W[(t-14)%16]^
                     W[(t-16)%16],1)
                  ));
        e = d;
        d = c;
        c = ROTL(b,30);
        b = a;
        a = T;
    }

    // Accumulation.
    
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;    
}

static const uint32_t K_sha256[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void compressfunc_sha256(uint32_t H[8], uint32_t const *restrict M)
{
#define Sigma0(x) ( ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22) )
#define Sigma1(x) ( ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25) )
#define sigma0(x) ( ROTR(x,7) ^ ROTR(x,18) ^ (x>>3) )
#define sigma1(x) ( ROTR(x,17) ^ ROTR(x,19) ^ (x>>10) )

    // Working Variables.
    uint32_t a, b, c, d, e, f, g, h, T1, T2, W[16];
    int t;
    
    for(t=0; t<16; t++) W[t] = be32toh(M[t]);

    // Initializing Working Variables.
    
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    // Computation Body + Message Schedule.

    for(t=0; t<64; t++) {
        T1 = h + Sigma1(e) + Ch(e,f,g) + K_sha256[t] + (
            t<16 ?
            W[t] :
            (W[t%16] =
             sigma1(W[( t-2 )%16]) + W[( t-7 )%16] +
             sigma0(W[( t-15 )%16]) + W[( t-16 )%16])
            );
        T2 = Sigma0(a) + Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // Accumulation.

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;

#undef Sigma0
#undef Sigma1
#undef sigma0
#undef sigma1
}

#undef ROTL
#undef ROTR
// to silence unused macro warning. 
// #define ROTL(x,n) (( (x)<<(n) )|( (x)>>(64-(n)) )) 
#define ROTR(x,n) (( (x)>>(n) )|( (x)<<(64-(n)) ))

static const uint64_t K_sha512[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

void compressfunc_sha512(uint64_t H[8], uint64_t const *restrict M)
{
#define Sigma0(x) ( ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39) )
#define Sigma1(x) ( ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41) )
#define sigma0(x) ( ROTR(x,1) ^ ROTR(x,8) ^ (x>>7) )
#define sigma1(x) ( ROTR(x,19) ^ ROTR(x,61) ^ (x>>6) )
    
    // Working Variables.
    uint64_t a, b, c, d, e, f, g, h, T1, T2, W[16];
    int t;
    
    for(t=0; t<16; t++) W[t] = be64toh(M[t]);

    // Initializing Working Variables.
    
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    // Computation Body + Message Schedule.

    for(t=0; t<80; t++) {
        T1 = h + Sigma1(e) + Ch(e,f,g) + K_sha512[t] + (
            t<16 ?
            W[t] :
            (W[t%16] =
             sigma1(W[( t-2 )%16]) + W[( t-7 )%16] +
             sigma0(W[( t-15 )%16]) + W[( t-16 )%16])
            );
        T2 = Sigma0(a) + Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // Accumulation.

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;

#undef Sigma0
#undef Sigma1
#undef sigma0
#undef sigma1
}
