/* DannyNiu/NJF, 2018-02-05. Public Domain. */

#ifndef MySuiteA_sm3_h
#define MySuiteA_sm3_h 1

#include "../mysuitea-common.h"

typedef struct sm3_context {
    int         finalized;
    unsigned    filled;
    uint64_t    len;
    uint32_t    H[8];
    union {
        uint32_t    Msg32[16];
        uint8_t     Msg8[64];
    };
} sm3_t;

void SM3_Init(sm3_t *restrict sm3);
void SM3_Update(sm3_t *restrict sm3, void const *restrict data, size_t len);
void SM3_Final(sm3_t *restrict sm3, void *restrict out, size_t t);

#define cSM3(q) (                                      \
        q==outBytes ? 32 :                             \
        q==blockBytes ? 64 :                           \
        q==contextBytes ? sizeof(struct sm3_context) : \
        q==InitFunc   ? (IntPtr)SM3_Init :             \
        q==UpdateFunc ? (IntPtr)SM3_Update :           \
        q==FinalFunc  ? (IntPtr)SM3_Final :            \
        0)
IntPtr iSM3(int q);

#endif