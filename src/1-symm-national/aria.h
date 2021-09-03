/* DannyNiu/NJF, 2021-07-19. Public Domain. */

#ifndef MySuiteA_aria_h
#define MySuiteA_aria_h 1

#include "../mysuitea-common.h"

void ARIA128_KeySched(void const *restrict key, void *restrict w);
void ARIA192_KeySched(void const *restrict key, void *restrict w);
void ARIA256_KeySched(void const *restrict key, void *restrict w);

void ARIA128_Encrypt(void const *in, void *out, void const *restrict w);
void ARIA256_Encrypt(void const *in, void *out, void const *restrict w);

void ARIA128_Decrypt(void const *in, void *out, void const *restrict w);
void ARIA256_Decrypt(void const *in, void *out, void const *restrict w);

#define cARIA(bits,q) (                                 \
        q==blockBytes ? 16 :                            \
        q==keyBytes ? (bits)/8 :                        \
        q==keyschedBytes ? ((bits)/32+8+1)*16 :         \
        0)

#define xARIA(bits,q) (                                 \
        q==EncFunc ? (IntPtr)ARIA##bits##_Encrypt :     \
        q==DecFunc ? (IntPtr)ARIA##bits##_Decrypt :     \
        q==KschdFunc ? (IntPtr)ARIA##bits##_KeySched :  \
        cARIA(bits,q) )

#define cARIA128(q) cARIA(128,q)
#define cARIA192(q) cARIA(192,q)
#define cARIA256(q) cARIA(256,q)

#define xARIA128(q) xARIA(128,q)
#define xARIA192(q) xARIA(192,q)
#define xARIA256(q) xARIA(256,q)

IntPtr iARIA128(int q);
IntPtr iARIA192(int q);
IntPtr iARIA256(int q);

#endif /* MySuiteA_aria_h */
