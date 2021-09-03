/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#ifndef MySuiteA_gimli_hash_h
#define MySuiteA_gimli_hash_h 1

#include "../mysuitea-common.h"
#include "../1-symm/sponge.h"

typedef struct gimli_xof_context {
    sponge_t    sponge;
    union {
        uint8_t     u8[48];
        uint32_t    u32[12];
    } state;
} gimli_xof_t;

void Gimli_XOF_Init(gimli_xof_t *restrict x);
void Gimli_XOF_Write(
    gimli_xof_t *restrict x,
    void const *restrict data,
    size_t len);
void Gimli_XOF_Final(gimli_xof_t *restrict x);
void Gimli_XOF_Read(gimli_xof_t *restrict x, void *restrict data, size_t len);

#define cGimli_XOF(q) (                                         \
        q==blockBytes ? 16 :                                    \
        q==contextBytes ? sizeof(struct gimli_xof_context) :    \
        0)

#define xGimli_XOF(q) (                                         \
        q==InitFunc ? (IntPtr)Gimli_XOF_Init :                  \
        q==WriteFunc ? (IntPtr)Gimli_XOF_Write :                \
        q==XofFinalFunc ? (IntPtr)Gimli_XOF_Final :             \
        q==ReadFunc ? (IntPtr)Gimli_XOF_Read :                  \
        cGimli_XOF(q) )

IntPtr iGimli_XOF(int q);

#endif /* MySuiteA_gimli_hash_h */
