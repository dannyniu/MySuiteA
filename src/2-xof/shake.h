/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#ifndef MySuiteA_shake_h
#define MySuiteA_shake_h 1

#include "../mysuitea-common.h"
#include "../1-symm/sponge.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: Error | 8 *53 | 8 *54
typedef struct shake_context {
    sponge_t    sponge;
    union {
        uint8_t     u8[200];
        uint64_t    u64[25];
    } state[2];
} shake_t, shake128_t, shake256_t, cshake_t, cshake128_t, cshake256_t;

void SHAKE128_Init(shake_t *restrict x);
void SHAKE256_Init(shake_t *restrict x);
void SHAKE_Write(shake_t *restrict x, const void *restrict data, size_t len);
void SHAKE_Final(shake_t *restrict x);
void SHAKE_Read(shake_t *restrict x, void *restrict data, size_t len);

void cshake_left_encode(cshake_t *restrict x, uint64_t v);
void cshake_right_encode(cshake_t *restrict x, uint64_t v);
void cshake_encode_string(
    cshake_t *restrict x,
    const void *restrict S,
    size_t len);

void *SHAKE_Xctrl(
    shake_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

enum {
    SHAKE_cmd_null          = 0,

    // this subfunction discards all previously absorbed data.
    // within `bufvec':
    // 0: N - "function name",
    // 1: S - "customization",
    SHAKE_cSHAKE_customize  = 1,
};

#define cSHAKE(bits,q) (                                        \
        q==outBytes ? -1 :                                      \
        q==outTruncBytes ? ((bits * 2) / 8) :                   \
        q==blockBytes ? (1600-bits*2)/8 :                       \
        q==contextBytes ? sizeof(struct shake_context) :        \
        0)

#define xSHAKE(bits,q) (                                        \
        q==InitFunc ? (IntPtr)SHAKE##bits##_Init :              \
        q==WriteFunc ? (IntPtr)SHAKE_Write :                    \
        q==XofFinalFunc ? (IntPtr)SHAKE_Final :                 \
        q==ReadFunc ? (IntPtr)SHAKE_Read :                      \
        q==XctrlFunc ? (IntPtr)SHAKE_Xctrl :                    \
        cSHAKE(bits,q) )

#define cSHAKE128(q) cSHAKE(128,q)
#define cSHAKE256(q) cSHAKE(256,q)

#define xSHAKE128(q) xSHAKE(128,q)
#define xSHAKE256(q) xSHAKE(256,q)

IntPtr iSHAKE128(int q);
IntPtr iSHAKE256(int q);

#endif /* MySuiteA_shake_h */
