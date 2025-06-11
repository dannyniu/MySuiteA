/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#include "keccak.h"
#include "../0-datum/endian.h"
#include <arm_neon.h>

#define Keccak_StateSize 1600
#define keccak_word_t uint64_t

#define KeccakP_InstName glue(KeccakP,Keccak_StateSize)

#define w (sizeof(keccak_word_t) * 8)
#define l (w==64?6 : w==32?5 : w==16?4 : w==8?3 : w==4?2 : w==2?1 : 0)

#define theta   glue(keccak_word_t,__theta)
#define rho     glue(keccak_word_t,__rho)
#define pi      glue(keccak_word_t,__pi)
#define chi     glue(keccak_word_t,__chi)
#define iota    glue(keccak_word_t,__iota)

typedef uint64_t keccak1600_state_t[5][5];

static inline void theta64(keccak1600_state_t A)
{
    uint64x2_t C[4], D, T;
    register int y;

    C[0] =
        veor3q_u64(
            veor3q_u64(
                vcombine_u64(vcreate_u64(A[0][4]), vcreate_u64(A[0][0])),
                vcombine_u64(vcreate_u64(A[1][4]), vcreate_u64(A[1][0])),
                vcombine_u64(vcreate_u64(A[2][4]), vcreate_u64(A[2][0])) ),
            vcombine_u64(vcreate_u64(A[3][4]), vcreate_u64(A[3][0])),
            vcombine_u64(vcreate_u64(A[4][4]), vcreate_u64(A[4][0])) );
    
    C[1] =
        veor3q_u64(
            veor3q_u64(
                vcombine_u64(vcreate_u64(A[0][1]), vcreate_u64(A[0][2])),
                vcombine_u64(vcreate_u64(A[1][1]), vcreate_u64(A[1][2])),
                vcombine_u64(vcreate_u64(A[2][1]), vcreate_u64(A[2][2])) ),
            vcombine_u64(vcreate_u64(A[3][1]), vcreate_u64(A[3][2])),
            vcombine_u64(vcreate_u64(A[4][1]), vcreate_u64(A[4][2])) );
    
    C[2] =
        veor3q_u64(
            veor3q_u64(
                vcombine_u64(vcreate_u64(A[0][3]), vcreate_u64(A[0][4])),
                vcombine_u64(vcreate_u64(A[1][3]), vcreate_u64(A[1][4])),
                vcombine_u64(vcreate_u64(A[2][3]), vcreate_u64(A[2][4])) ),
            vcombine_u64(vcreate_u64(A[3][3]), vcreate_u64(A[3][4])),
            vcombine_u64(vcreate_u64(A[4][3]), vcreate_u64(A[4][4])) );

    C[3] =
        veor3q_u64(
            veor3q_u64(
                vcombine_u64(vcreate_u64(A[0][0]), vcreate_u64(A[0][1])),
                vcombine_u64(vcreate_u64(A[1][0]), vcreate_u64(A[1][1])),
                vcombine_u64(vcreate_u64(A[2][0]), vcreate_u64(A[2][1])) ),
            vcombine_u64(vcreate_u64(A[3][0]), vcreate_u64(A[3][1])),
            vcombine_u64(vcreate_u64(A[4][0]), vcreate_u64(A[4][1])) );

    D = vrax1q_u64(C[0], C[1]);
    for(y=0; y<5; y++)
    {
        T = vcombine_u64(vcreate_u64(A[y][0]), vcreate_u64(A[y][1]));
        T = veorq_u64(T, D);
        A[y][0] = vdupd_laneq_u64(T, 0);
        A[y][1] = vdupd_laneq_u64(T, 1);
    }

    D = vrax1q_u64(C[1], C[2]);
    for(y=0; y<5; y++)
    {
        T = vcombine_u64(vcreate_u64(A[y][2]), vcreate_u64(A[y][3]));
        T = veorq_u64(T, D);
        A[y][2] = vdupd_laneq_u64(T, 0);
        A[y][3] = vdupd_laneq_u64(T, 1);
    }

    D = vrax1q_u64(C[2], C[3]);
    for(y=0; y<5; y++)
    {
        T = vcombine_u64(vcreate_u64(A[y][4]), vcreate_u64(0));
        T = veorq_u64(T, D);
        A[y][4] = vdupd_laneq_u64(T, 0);
    }
}

static inline void rho(keccak1600_state_t A);
static inline void pi(keccak1600_state_t A);

static inline void chi64(keccak1600_state_t A)
{
    // int x, y; // for the reference code.
    int y; // for the optimized code.
    for(y=0; y<5; y++)
    {
        // Reference code.
        /* for(x=0; x<5; x++)
         * A_out[y][x] = A[y][x] ^ ( ~A[y][ mod5(x+1) ] & A[y][ mod5(x+2) ] );
         */

        // Been optimized (2022-10-03).
        uint64x2_t V[5], T;

        V[0] = vcombine_u64(vcreate_u64(A[y][0]), vcreate_u64(A[y][1]));
        V[1] = vcombine_u64(vcreate_u64(A[y][2]), vcreate_u64(A[y][3]));
        V[2] = vcombine_u64(vcreate_u64(A[y][4]), vcreate_u64(A[y][0]));
        V[3] = vcombine_u64(vcreate_u64(A[y][1]), vcreate_u64(A[y][2]));
        V[4] = vcombine_u64(vcreate_u64(A[y][3]), vcreate_u64(A[y][4]));

        T = vbcaxq_u64(V[0], V[1], V[3]);
        A[y][0] = vdupd_laneq_u64(T, 0);
        A[y][1] = vdupd_laneq_u64(T, 1);
        
        T = vbcaxq_u64(V[1], V[2], V[4]);
        A[y][2] = vdupd_laneq_u64(T, 0);
        A[y][3] = vdupd_laneq_u64(T, 1);

        T = vbcaxq_u64(V[2], V[3], V[0]);
        A[y][4] = vdupd_laneq_u64(T, 0);
    }
}

static inline int iota(keccak1600_state_t A, int lfsr);

// Intentionally not restrict-qualified.
void glue(KeccakP_InstName,_Permute_ni)(void const *in, void *out, int rounds)
{
    uint64_t const *cptr;
    uint64_t *ptr;
    int lfsr = 1;

    int i;
    int ir;

    cptr = in;
    ptr = out;
    for(i=0; i<25; i++) ptr[i] = le64toh(cptr[i]);

    i = 12+2*l;
    for(ir = 0; ir<i; ir++) {
        if( ir+rounds >= i )
            theta64(out), rho(out), pi(out), chi64(out);
        lfsr = iota(ir+rounds >= i ? out : NULL, lfsr);
    }

    for(i=0; i<25; i++) ptr[i] = htole64(ptr[i]);
}

#define IntrinSelf
#include "keccak-f-1600.c"
