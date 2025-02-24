/* DannyNiu/NJF, 2022-09-06. Public Domain. */

#ifndef MySuiteA_KangarooTwelve_h
#define MySuiteA_KangarooTwelve_h 1

#include "../mysuitea-common.h"
#include "../1-symm/keccak.h"
#include "../1-symm/sponge.h"

// [2024-03-17-turboshake-omission]:
// The construction of TurboSHAKE is simple enough that a straightforward
// combination of KeccakP1600nr12 with the publicly exposed sponge
// interfaces are sufficient for instantiation.
//
// If one were to provide a full implementation of TurboSHAKE, then
// domain separation byte will have to be implemented with a
// full-blown context control function, which may be inflexible.

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 2*4100| 4*2050| 8*1025
typedef struct {
    uint16_t me;
    uint16_t hashed;
    uint32_t filled;
    uint8_t buf[8192];
} k12_inner_node_t;

// This parameter tunes the parallelism of the hashing context.
// Unlike BLAKE-3 where an actual tree is involved, K12 and M14
// don't need to keep track of branch nodes, so this can be
// decreased as one sees fit.
#define K12_NODES_COUNT 64 // this is ''p''

// data model:        SIP16       |       ILP32      |        LP64
// ----------+--------------------+------------------+------------------
// align spec: 2*(4100*p+6+100+16)| 4*(2050*p+6+50+8)| 8*(1025*p+4+25+4)
typedef struct {
    k12_inner_node_t inodes[K12_NODES_COUNT];
    struct {
        sponge_t sponge;
        union {
            uint8_t u8[200];
            uint64_t u64[25];
        } buf;
    } finalnode;
    uint64_t total;
    uint64_t clen;
    uint64_t inodes_filled;
    uint64_t finalized;
} K12_Ctx_t, KT128_t, KT256_t, KangarooTwelve_t, MarsupilamiFourteen_t;

void KT128_Init(KT128_t *x);
void KT256_Init(KT256_t *x);
#define KangarooTwelve_Init KT128_Init
void MarsupilamiFourteen_Init(KangarooTwelve_t *x);

void K12_Update4(
    K12_Ctx_t *restrict x,
    void const *restrict dat,
    size_t len,
    TCrew_Abstract_t *restrict tc);

void K12_Final2(K12_Ctx_t *restrict x, TCrew_Abstract_t *restrict tc);

void K12_Read4(
    K12_Ctx_t *restrict x,
    void *restrict out,
    size_t len, int flags);

void *K12_Xctrl(
    K12_Ctx_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

enum {
    K12_cmd_null        = 0,

    // Feed customization string.
    // The length and the pointer to the
    // customization string (whole or parts) are in bufvec[0].
    // The threads crew object is in bufvec[1].buf,
    K12_cmd_Feed_CStr   = 1,
};

#define cKT128(q) (                                     \
        q==outBytes ? -1 :                              \
        q==outTruncBytes ? 32 :                         \
        q==blockBytes ? 200-32 :                        \
        q==chunkBytes ? 8192 :                          \
        q==contextBytes ? (IntPtr)sizeof(K12_Ctx_t) :   \
        0)

#define xKT128(q) (                             \
        q==InitFunc    ? (IntPtr)KT128_Init :   \
        q==Update4Func ? (IntPtr)K12_Update4 :  \
        q==Final2Func  ? (IntPtr)K12_Final2 :   \
        q==Read4Func   ? (IntPtr)K12_Read4 :    \
        q==XctrlFunc   ? (IntPtr)K12_Xctrl :    \
        cKT128(q) )

#define cKT256(q) (                                     \
        q==outBytes ? -1 :                              \
        q==outTruncBytes ? 64 :                         \
        q==blockBytes ? 200-64 :                        \
        q==chunkBytes ? 8192 :                          \
        q==contextBytes ? (IntPtr)sizeof(K12_Ctx_t) :   \
        0)

#define xKT256(q) (                             \
        q==InitFunc    ? (IntPtr)KT256_Init :   \
        q==Update4Func ? (IntPtr)K12_Update4 :  \
        q==Final2Func  ? (IntPtr)K12_Final2 :   \
        q==Read4Func   ? (IntPtr)K12_Read4 :    \
        q==XctrlFunc   ? (IntPtr)K12_Xctrl :    \
        cKT256(q) )

#define cKangarooTwelve(q) cKT128(q)
#define xKangarooTwelve(q) xKT128(q)

#define cMarsupilamiFourteen(q) (                       \
        q==outBytes ? -1 :                              \
        q==outTruncBytes ? 64 :                         \
        q==blockBytes ? 200-64 :                        \
        q==chunkBytes ? 8192 :                          \
        q==contextBytes ? (IntPtr)sizeof(K12_Ctx_t) :   \
        0)

#define xMarsupilamiFourteen(q) (                               \
        q==InitFunc    ? (IntPtr)MarsupilamiFourteen_Init :     \
        q==Update4Func ? (IntPtr)K12_Update4 :                  \
        q==Final2Func  ? (IntPtr)K12_Final2 :                   \
        q==Read4Func   ? (IntPtr)K12_Read4 :                    \
        q==XctrlFunc   ? (IntPtr)K12_Xctrl :                    \
        cMarsupilamiFourteen(q) )

IntPtr iKT128(int q);
IntPtr iKT256(int q);
IntPtr iMarsupilamiFourteen(int q);

#define iKangarooTwelve(q) iKT128(q)

#endif /* MySuiteA_KangarooTwelve_h */
