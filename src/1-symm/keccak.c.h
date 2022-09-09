/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#if defined(Keccak_StateSize) && defined(keccak_word_t)

#define KeccakF_InstName glue(KeccakF,Keccak_StateSize)
#define KeccakP_InstName glue(KeccakP,Keccak_StateSize)
#define keccak_state_t glue(glue(keccak_state,Keccak_StateSize),_t)

#define w (sizeof(keccak_word_t) * 8)
#define l (w==64?6 : w==32?5 : w==16?4 : w==8?3 : w==4?2 : w==2?1 : 0)

#define rot     glue(keccak_word_t,__rot)

#define theta   glue(keccak_word_t,__theta)
#define rho     glue(keccak_word_t,__rho)
#define pi      glue(keccak_word_t,__pi)
#define chi     glue(keccak_word_t,__chi)
#define iota    glue(keccak_word_t,__iota)

typedef keccak_word_t keccak_state_t[5][5];

// #define A(x,y,z) ((A[y][x]>>z)&1) // helps you remember.

static inline keccak_word_t rot(keccak_word_t x, int s) // rotate-left.
{
    register unsigned u = (unsigned)s & (w-1);
    return u ? ( x << u ) | ( x >> (w-u) ) : x;
}

#ifndef Keccak_mod5_defined
#define Keccak_mod5_defined
static inline int mod5(int x) // x shall never be data-dependent.
{
    // ad-hoc, but efficient here.
    while( x >= 5 ) x -= 10;
    while( x < 0 ) x += 5;
    return x;
}
#endif /* Keccak_mod5_defined */

#include "../0-datum/endian.h"

// 2020-07-09:
// This isn't the correct way to use ``_Generic'',
// but exception is allowed here for the ``uint8_t'' case.

#define letoh(x)                                \
    _Generic(x,                                 \
             uint8_t:(x),                       \
             uint16_t:le16toh(x),               \
             uint32_t:le32toh(x),               \
             uint64_t:le64toh(x)                \
        )
#define htole(x)                                \
    _Generic(x,                                 \
             uint8_t:(x),                       \
             uint16_t:htole16(x),               \
             uint32_t:htole32(x),               \
             uint64_t:htole64(x)                \
        )

static inline void theta(keccak_state_t A)
{
    keccak_word_t C[5];
    register int x, y;

    for(x=0; x<5; x++)
        C[x] =
            A[0][x] ^
            A[1][x] ^
            A[2][x] ^
            A[3][x] ^
            A[4][x] ;

    for(x=0; x<5; x++)
    {
        keccak_word_t D = C[ mod5(x-1) ] ^ rot( C[ mod5(x+1) ] , 1 );
        for(y=0; y<5; y++) A[y][x] = A[y][x] ^ D;
    }
}

static inline void rho(keccak_state_t A)
{
    int x=1, y=0;
    int t;

    //A_out[0][0] = A[0][0];

    for(t=0; t<24; t++)
    {
        int x2 = y, y2 = mod5( 2*x+3*y );
        A[y][x] = rot( A[y][x] , ((t+1)*(t+2))>>1 );

        x = x2;
        y = y2;
    }
}

static inline void pi(keccak_state_t A)
{
    // Reference code,
    /* int x, y;
    for(y=0; y<5; y++) for(x=0; x<5; x++) A_out[y][x] = A[x][ mod5(x+3*y) ]; */

    // Been optimized (2022-09-06).
    keccak_word_t u;
    u = A[1][0];
    A[1][0] = A[0][3];
    A[0][3] = A[3][3];
    A[3][3] = A[3][2];
    A[3][2] = A[2][1];
    A[2][1] = A[1][2];
    A[1][2] = A[2][0];
    A[2][0] = A[0][1];
    A[0][1] = A[1][1];
    A[1][1] = A[1][4];
    A[1][4] = A[4][2];
    A[4][2] = A[2][4];
    A[2][4] = A[4][0];
    A[4][0] = A[0][2];
    A[0][2] = A[2][2];
    A[2][2] = A[2][3];
    A[2][3] = A[3][4];
    A[3][4] = A[4][3];
    A[4][3] = A[3][0];
    A[3][0] = A[0][4];
    A[0][4] = A[4][4];
    A[4][4] = A[4][1];
    A[4][1] = A[1][3];
    A[1][3] = A[3][1];
    A[3][1] = u;
}

static inline void chi(keccak_state_t A)
{
    // int x, y; // for the reference code.
    int y; // for the optimized code.
    for(y=0; y<5; y++)
    {
        // Reference code.
        /* for(x=0; x<5; x++)
         * A_out[y][x] = A[y][x] ^ ( ~A[y][ mod5(x+1) ] & A[y][ mod5(x+2) ] );
         */

        // Been optimized (2022-09-06).
        keccak_word_t u = A[y][0], v = A[y][1];
        A[y][0] ^= ~A[y][1] & A[y][2];
        A[y][1] ^= ~A[y][2] & A[y][3];
        A[y][2] ^= ~A[y][3] & A[y][4];
        A[y][3] ^= ~A[y][4] & u;
        A[y][4] ^= ~u & v;
    }
}

static inline int iota(keccak_state_t A, int lfsr)
{
    // int x, y;
    int j;
    keccak_word_t RC = 0;

    for(j=0; j<=6; j++)
    {
        if( j <= l )
            RC ^= ((keccak_word_t)lfsr&1) << ((1<<j)-1);

        lfsr <<= 1;
        lfsr ^= ((lfsr>>8)&1)*0x71;
        lfsr &= 0xff;
    }

    // 2022-09-06:
    // Added this condition so as to support 12-round Keccak-p with
    // ideally minimum amount of change to existing code.
    if( A ) A[0][0] ^= RC;
    
    return lfsr;
}

// Intentionally not restrict-qualified.
void glue(KeccakP_InstName,_Permute)(void const *in, void *out, int rounds)
{
    keccak_word_t const *cptr;
    keccak_word_t *ptr;
    int lfsr = 1;

    int i;
    int ir;

    cptr = in;
    ptr = out;
    for(i=0; i<25; i++) ptr[i] = letoh(cptr[i]);

    i = 12+2*l;
    for(ir = 0; ir<i; ir++) {
        if( ir+rounds >= i )
            theta(out), rho(out), pi(out), chi(out);
        lfsr = iota(ir+rounds >= i ? out : NULL, lfsr);
    }

    for(i=0; i<25; i++) ptr[i] = htole(ptr[i]);
}

// Intentionally not restrict-qualified.
void glue(KeccakF_InstName,_Permute)(void const *in, void *out)
{
    glue(KeccakP_InstName,_Permute)(in, out, 24);
}

IntPtr glue(i,KeccakF_InstName)(int q){ return glue(x,KeccakF_InstName)(q); }

#endif /* defined(Keccak_StateSize) && defined(keccak_word_t) */
