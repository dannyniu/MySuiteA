/* DannyNiu/NJF, 2022-04-14. Public Domain. */

#ifndef MySuiteA_kmac_h
#define MySuiteA_kmac_h 1

#include "../2-xof/shake.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: Error | 8 *53 | 8 *54
typedef shake_t kmac_t, kmac128_t, kmac256_t;

void *KMAC_VInit(
    kmac_t *restrict kmac,
    const void *restrict k, size_t klen,
    const void *restrict s, size_t slen,
    unsigned rate);

void *KMAC128_Init(
    kmac128_t *restrict kmac,
    void const *restrict key,
    size_t keylen);

void *KMAC256_Init(
    kmac256_t *restrict kmac,
    void const *restrict key,
    size_t keylen);

void *KMAC128_Xctrl(
    kmac128_t *restrict kmac,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

void *KMAC256_Xctrl(
    kmac256_t *restrict kmac,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

enum {
    KMAC_cmd_null       = 0,

    // this subfunction initializes a KMAC working context with
    // a key, and a customization string denoted as 'S'.
    // within `bufvec':
    // 0: S - the customization string.
    // 1: K - the KMAC key.
    KMAC_KInit_WithS    = 1,
};

void KMAC_Update(
    kmac_t *restrict kmac, void const *restrict data, size_t len);

void KMAC_Final(
    kmac_t *restrict kmac, void *restrict out, size_t t);

void KMAC_XofFinal(kmac_t *restrict kmac);
void KMAC_XofRead(kmac_t *restrict kmac, void *restrict out, size_t t);

#define cKMAC(bits,q) (                                         \
        q==outBytes ? -1 :                                      \
        q==outTruncBytes ? ((bits * 2) / 8) :                   \
        q==blockBytes ? (200 - (bits / 8) * 2) :                \
        q==keyBytes ? -((bits / 8) * 2) :                       \
        q==contextBytes ? (IntPtr)sizeof(kmac##bits##_t) :      \
        0)

#define xKMAC(bits,q) (                                 \
        q==KInitFunc ? (IntPtr)KMAC##bits##_Init :      \
        q==UpdateFunc ? (IntPtr)KMAC_Update :           \
        q==FinalFunc ? (IntPtr)KMAC_Final :             \
        q==XofFinalFunc ? (IntPtr)KMAC_XofFinal :       \
        q==ReadFunc ? (IntPtr)KMAC_XofRead :            \
        q==XctrlFunc ? (IntPtr)KMAC##bits##_Xctrl :     \
        cKMAC(bits,q) )

#define cKMAC128(q) cKMAC(128,q)
#define cKMAC256(q) cKMAC(256,q)

#define xKMAC128(q) xKMAC(128,q)
#define xKMAC256(q) xKMAC(256,q)

IntPtr iKMAC128(int q);
IntPtr iKMAC256(int q);

#endif /* MySuiteA_kmac_h */
