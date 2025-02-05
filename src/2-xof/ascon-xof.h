/* DannyNiu/NJF, 2025-01-27. Public Domain. */

#ifndef MySuiteA_ascon_xof_h
#define MySuiteA_ascon_xof_h 1

#include "../1-symm/ascon-permutation.h"
#include "../1-symm/sponge.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: Error | 8 *13 | 8 *14
typedef struct {
    sponge_t sponge;
    union {
        uint8_t u8[40];
        uint64_t u64[5];
    } state[2];
} ascon_xof128_t, ascon_cxof128_t;

void Ascon_XOF128_Init(ascon_xof128_t *restrict x);

void Ascon_CXOF128_KInit(
    ascon_cxof128_t *restrict x, const void *restrict Z, size_t len);

void Ascon_XOF128_Write(
    ascon_xof128_t *restrict x, const void *restrict data, size_t len);

void Ascon_XOF128_Final(ascon_xof128_t *restrict x);

void Ascon_XOF128_Read(
    ascon_xof128_t *restrict x, void *restrict data, size_t len);

#define cAscon_XOF128(q) (                                      \
        q==outBytes ? -1 :                                      \
        q==outTruncBytes ? 32 :                                 \
        q==blockBytes ? 8 :                                     \
        q==contextBytes ? sizeof(struct ascon_xof128_t) :       \
        0)

#define xAscon_XOF128(q) (                              \
        q==InitFunc ? (IntPtr)Ascon_XOF128_Init :       \
        q==KInitFunc ? (IntPtr)Ascon_CXOF128_KInit :    \
        q==WriteFunc ? (IntPtr)Ascon_XOF128_Write :     \
        q==XofFinalFunc ? (IntPtr)Ascon_XOF128_Final :  \
        q==ReadFunc ? (IntPtr)Ascon_XOF128_Read :       \
        cSHAKE(bits,q) )

IntPtr iAscon_XOF128(int q);

#endif /* MySuiteA_ascon_xof_h */
