/* DannyNiu/NJF, 2021-06-23. Public Domain. */

#ifndef MySuiteA_camellia_h
#define MySuiteA_camellia_h 1

#include "../mysuitea-common.h"

typedef struct {
    uint64_t K_LL, K_LR, K_AL, K_AR;
} camellia128_kschd_t;

typedef struct {
    // It is intended that camellia128_kschd_t
    // be a prefix of camellia{192,256}_kschd_t.
    uint64_t K_LL, K_LR, K_AL, K_AR;
    uint64_t K_RL, K_RR, K_BL, K_BR;
} camellia192_kschd_t, camellia256_kschd_t;

void Camellia128_KeySched(void const *restrict key, void *restrict w);
void Camellia192_KeySched(void const *restrict key, void *restrict w);
void Camellia256_KeySched(void const *restrict key, void *restrict w);

void Camellia128_Encrypt(void const *in, void *out, void const *restrict w);
void Camellia256_Encrypt(void const *in, void *out, void const *restrict w);

void Camellia128_Decrypt(void const *in, void *out, void const *restrict w);
void Camellia256_Decrypt(void const *in, void *out, void const *restrict w);

#define Camellia192_Encrypt Camellia256_Encrypt
#define Camellia192_Decrypt Camellia256_Decrypt

#define cCamellia(bits,q) (                                     \
        q==blockBytes ? 16 :                                    \
        q==keyBytes ? (bits)/8 :                                \
        q==keyschedBytes ? sizeof(camellia##bits##_kschd_t) :   \
        0)

#define xCamellia(bits,q) (                                     \
        q==EncFunc ? (IntPtr)Camellia##bits##_Encrypt :         \
        q==DecFunc ? (IntPtr)Camellia##bits##_Decrypt :         \
        q==KschdFunc ? (IntPtr)Camellia##bits##_KeySched :      \
        cCamellia(bits,q) )

#define cCamellia128(q) cCamellia(128,q)
#define cCamellia192(q) cCamellia(192,q)
#define cCamellia256(q) cCamellia(256,q)

#define xCamellia128(q) xCamellia(128,q)
#define xCamellia192(q) xCamellia(192,q)
#define xCamellia256(q) xCamellia(256,q)

IntPtr iCamellia128(int q);
IntPtr iCamellia192(int q);
IntPtr iCamellia256(int q);

#endif /* MySuiteA_camellia_h */
