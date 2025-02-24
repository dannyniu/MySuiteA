/* DannyNiu/NJF, 2021-06-21. Public Domain. */

#ifndef MySuiteA_sm4_h
#define MySuiteA_sm4_h 1

#include "../mysuitea-common.h"

void SM4Encrypt(void const *in, void *out, void const *restrict w);
void SM4Decrypt(void const *in, void *out, void const *restrict w);
void SM4KeySched(void const *restrict key, void *restrict w);

void NI_SM4Encrypt(void const *in, void *out, void const *restrict w);
void NI_SM4Decrypt(void const *in, void *out, void const *restrict w);
void NI_SM4KeySched(void const *restrict key, void *restrict w);

#define cSM4(q) (                               \
        q==blockBytes ? 16 :                    \
        q==keyBytes ? 16 :                      \
        q==keyschedBytes ? (32 * 4) :           \
        0)

#if !defined(NI_SM4) || NI_SM4 == NI_NEVER
#define xSM4(q) (                               \
        q==EncFunc ? (IntPtr)SM4Encrypt :       \
        q==DecFunc ? (IntPtr)SM4Decrypt :       \
        q==KschdFunc ? (IntPtr)SM4KeySched :    \
        cSM4(q) )

#elif NI_SM4 == NI_ALWAYS
#define DEF_INC_FROM_NI
#define xSM4(q) (                                  \
        q==EncFunc ? (IntPtr)NI_SM4Encrypt :       \
        q==DecFunc ? (IntPtr)NI_SM4Decrypt :       \
        q==KschdFunc ? (IntPtr)NI_SM4KeySched :    \
        cSM4(q) )

#elif NI_SM4 == NI_RUNTIME
#define DEF_INC_FROM_NI
extern int extern_ni_sm4_conf;
#define ni_sm4_conf extern_ni_sm4_conf

#define xSM4(q) (                                  \
        q==EncFunc ? (ni_sm4_conf ?                \
                      (IntPtr)NI_SM4Encrypt :      \
                      (IntPtr)   SM4Encrypt ) :    \
        q==DecFunc ? (ni_sm4_conf ?                \
                      (IntPtr)NI_SM4Decrypt :      \
                      (IntPtr)   SM4Decrypt ) :    \
        q==KschdFunc ? (ni_sm4_conf ?              \
                        (IntPtr)NI_SM4KeySched :   \
                        (IntPtr)   SM4KeySched ) : \
        cSM4(q) )
#endif /* NI_SM4 */

IntPtr iSM4(int q);

#endif /* MySuiteA_sm4_h */
