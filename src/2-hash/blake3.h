/* DannyNiu/NJF, 2022-08-17. Public Domain. */

#ifndef MySuiteA_blake3_h
#define MySuiteA_blake3_h 1

#include "../mysuitea-common.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:         8*131
typedef struct {
    uint8_t hashed;
    uint8_t height; // 0: leaf; >0: parent; max: root.
    uint16_t remain; // as in remain yet to be hashed, <= 1024.
    uint32_t d; // domain parameters (as with the spec).
    uint64_t t;
    int64_t me;
    union {
        uint8_t u8[1024];
        uint32_t u32[256];
    } buf;
} blake3_node_t;

// This number, and the type for some of the structure members, are chosen
// so that the entire structure pads up to multiply of 8 bytes (64 bits).
//
// The number of nodes in the working context must be at least 64, so as to
// ensure it can hold the deepest possible tree that can ever occur
// according to the spec.
//
#define BLAKE3_NODES_COUNT 65

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:   8*(5+17+131*65)
typedef struct {
    union {
        uint8_t u8[32];
        uint32_t u32[8];
    } k;

    uint64_t t;


    // no need to explain.
    int8_t keyed;
    int8_t finalize;

    // nodes[ nind[branches_filled + leaves_filled] ] is the
    // next node available to fill more (chunk) data.
    int16_t leaves_filled;

    // the number of branch nodes remain here.
    int16_t branches_filled;

    // index into ``nodes''
    int16_t nind[BLAKE3_NODES_COUNT];

    // storage of nodes, mapped by ``nind''.
    blake3_node_t nodes[BLAKE3_NODES_COUNT];
} blake3_t;

void BLAKE3_Init(blake3_t *x);

void BLAKE3_Update4(
    blake3_t *restrict x,
    void const *restrict dat,
    size_t len,
    TCrew_Abstract_t *restrict tc);

void BLAKE3_Final2(blake3_t *restrict x, TCrew_Abstract_t *restrict tc);

void BLAKE3_Read4(
    blake3_t *restrict x,
    void *restrict out,
    size_t len, int flags);

#define cBLAKE3(q) (                            \
        q==outBytes ? -1 :                      \
        q==blockBytes ? 64:                     \
        q==chunkBytes ? 1024 :                  \
        q==contextBytes ? sizeof(blake3_t) :    \
        0)

#define xBLAKE3(q) (                                    \
        q==InitFunc    ? (IntPtr)BLAKE3_Init :          \
        q==Update4Func ? (IntPtr)BLAKE3_Update4 :       \
        q==Final2Func  ? (IntPtr)BLAKE3_Final2 :        \
        q==Read4Func   ? (IntPtr)BLAKE3_Read4 :         \
        cBLAKE3(q) )

IntPtr iBLAKE3(int q);

#endif /* MySuiteA_blake3_h */
