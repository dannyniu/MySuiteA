/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#ifndef MySuiteA_shake_h
#define MySuiteA_shake_h 1

// References: src/notes.txt: "SHA3/Keccak". 

#include "../mysuitea-common.h"
#include "../1-symm/sponge.h"

typedef struct shake_context {
    sponge_t    sponge;
    union {
        uint8_t     u8[200];
        uint64_t    u64[25];
    } state;
} shake_t, shake128_t, shake256_t;

void SHAKE128_Init(shake_t *restrict x);
void SHAKE256_Init(shake_t *restrict x);
void SHAKE_Write(shake_t *restrict x, const void *restrict data, size_t len);
void SHAKE_Final(shake_t *restrict x);
void SHAKE_Read(shake_t *restrict x, void *restrict data, size_t len);

#ifndef foo
# // Emacs seems to have difficulty indent correctly if nothing's here. 
#endif /* foo */

#define _iSHAKE(bits,q) (                                       \
        q==blockBytes ? (1600-bits*2)/8 :                       \
        q==contextBytes ? sizeof(struct shake_context) :        \
        q==InitFunc ? (intptr_t)SHAKE##bits##_Init :            \
        q==WriteFunc ? (intptr_t)SHAKE_Write :                  \
        q==XofFinalFunc ? (intptr_t)SHAKE_Final :               \
        q==ReadFunc ? (intptr_t)SHAKE_Read :                    \
        -1)
#define _iSHAKE128(q) _iSHAKE(128,q)
#define _iSHAKE256(q) _iSHAKE(256,q)

intptr_t iSHAKE128(int q);
intptr_t iSHAKE256(int q);

#endif /* MySuiteA_shake_h */
