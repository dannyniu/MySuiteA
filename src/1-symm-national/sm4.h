/* DannyNiu/NJF, 2021-06-21. Public Domain. */

#ifndef MySuiteA_sm4_h
#define MySuiteA_sm4_h 1

#include "../mysuitea-common.h"

void SM4Encrypt(void const *in, void *out, void const *restrict w);
void SM4Decrypt(void const *in, void *out, void const *restrict w);
void SM4KeySched(void const *restrict key, void *restrict w);

#define cSM4(q) (                               \
        q==blockBytes ? 16 :                    \
        q==keyBytes ? 16 :                      \
        q==keyschedBytes ? (32 * 4) :           \
        q==EncFunc ? (IntPtr)SM4Encrypt :       \
        q==DecFunc ? (IntPtr)SM4Decrypt :       \
        q==KschdFunc ? (IntPtr)SM4KeySched :    \
        0)

IntPtr iSM4(int q);

#endif /* MySuiteA_sm4_h */
