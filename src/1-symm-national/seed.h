/* DannyNiu/NJR, 2021-07-18. Public Domain. */

#ifndef MySuiteA_seed_h
#define MySuiteA_seed_h 1

#include "../mysuitea-common.h"

void SEED_Encrypt(void const *in, void *out, void const *restrict w);
void SEED_Decrypt(void const *in, void *out, void const *restrict w);
void SEED_KeySched(void const *restrict key, void *restrict w);

#define cSEED(q) (                              \
        q==blockBytes ? 16 :                    \
        q==keyBytes ? 16 :                      \
        q==keyschedBytes ? (16 * 8) :           \
        0)

#define xSEED(q) (                              \
        q==EncFunc ? (IntPtr)SEED_Encrypt :     \
        q==DecFunc ? (IntPtr)SEED_Decrypt :     \
        q==KschdFunc ? (IntPtr)SEED_KeySched :  \
        cSEED(q) )

IntPtr iSEED(int q);

#endif /* MySuiteA_sm4_h */
