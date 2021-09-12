/* DannyNiu/NJF, 2021-07-20. Public Domain. */

#include "gbt-32905.h"
#include "../0-datum/endian.h"

static inline uint32_t T(int j)
{
    if( 0 <= j && j <= 15 ) return 0x79cc4519;
    if( 16 <= j && j <= 63 ) return 0x7a879d8a;
    return 0; // to silence a compiler warning. logically incorrect.
}

static inline uint32_t FF(
    int j, uint32_t X, uint32_t Y, uint32_t Z)
{
    if( 0 <= j && j <= 15 )
    {
        return X ^ Y ^ Z;
    }

    if( 16 <= j && j <= 63 )
    {
        return (X & Y) | (X & Z) | (Y & Z);
    }

    return 0; // to silence a compiler warning. logically incorrect.
}

static inline uint32_t GG(
    int j, uint32_t X, uint32_t Y, uint32_t Z)
{
    if( 0 <= j && j <= 15 )
    {
        return X ^ Y ^ Z;
    }

    if( 16 <= j && j <= 63 )
    {
        return (X & Y) | (~X & Z);
    }

    return 0; // to silence a compiler warning. logically incorrect.
}

static inline uint32_t P0(uint32_t X)
{
    return X ^ (X << 9 | X >> 23) ^ (X << 17 | X >> 15);
}

static inline uint32_t P1(uint32_t X)
{
    return X ^ (X << 15 | X >> 17) ^ (X << 23 | X >> 9);
}

void compressfunc_sm3(uint32_t V[8], uint32_t const *restrict M)
{
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    uint32_t W[16];
    int i, j;

    A = V[0];
    B = V[1];
    C = V[2];
    D = V[3];
    E = V[4];
    F = V[5];
    G = V[6];
    H = V[7];

    for(i=0; i<16; i++) W[i] = be32toh(M[i]);

    for(j=0; j<64; j++)
    {
        // SS1 := ((A <<< 12) + E + (T_j <<< (j % 32))) <<< 7
        // SS2 := SS1 ^ (A <<< 12)
        i = j % 32;
        SS1 = T(j);
        if( i ) SS1 = SS1 << i | SS1 >> (32 - i);
        SS1 += (A << 12 | A >> 20) + E;
        SS1 = SS1 << 7 | SS1 >> 25;
        SS2 = SS1 ^ (A << 12 | A >> 20);

        // TT1 := FF_j(A, B, C) + D + SS2 + W'_j
        // TT2 := GG_j(E, F, G) + H + SS1 + W_j
        i = j % 16;
        TT1 = W[i] ^ W[(i + 4) % 16];
        TT1 += FF(j, A, B, C) + D + SS2;
        TT2 = GG(j, E, F, G) + H + SS1 + W[i];
        
        // Update W[].
        W[i] = P1(
            W[i] ^
            W[(i + 7) % 16] ^
            (W[(i + 13) % 16] << 15 | W[(i + 13) % 16] >> 17)
            ) ^
            (W[(i + 3) % 16] << 7 | W[(i + 3) % 16] >> 25) ^
            W[(i + 10) % 16];

        // D := C
        // C := B <<< 9
        // B := A
        // A := TT1
        D = C;
        C = B << 9 | B >> 23;
        B = A;
        A = TT1;

        // H := G
        // G := F <<< 19
        // F := E
        // E := P0(TT2)
        H = G;
        G = F << 19 | F >> 13;
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A;
    V[1] ^= B;
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
}
