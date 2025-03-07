/* DannyNiu/NJF, 2018-01-31. Public Domain. */

#ifndef MySuiteA_rijndael_h
#define MySuiteA_rijndael_h 1

#include "../mysuitea-common.h"

void AES128_Cipher(void const *in, void *out, void const *restrict w);
void AES192_Cipher(void const *in, void *out, void const *restrict w);
void AES256_Cipher(void const *in, void *out, void const *restrict w);

void AES128_InvCipher(void const *in, void *out, void const *restrict w);
void AES192_InvCipher(void const *in, void *out, void const *restrict w);
void AES256_InvCipher(void const *in, void *out, void const *restrict w);

// declared but not defined if target platform doesn't support it.
void NI_AES128_Cipher(void const *in, void *out, void const *restrict w);
void NI_AES192_Cipher(void const *in, void *out, void const *restrict w);
void NI_AES256_Cipher(void const *in, void *out, void const *restrict w);

void NI_AES128_InvCipher(void const *in, void *out, void const *restrict w);
void NI_AES192_InvCipher(void const *in, void *out, void const *restrict w);
void NI_AES256_InvCipher(void const *in, void *out, void const *restrict w);

void AES128_KeyExpansion(void const *restrict key, void *restrict w);
void AES192_KeyExpansion(void const *restrict key, void *restrict w);
void AES256_KeyExpansion(void const *restrict key, void *restrict w);

#define cAES(bits,q) (                                          \
        q==blockBytes ? 16 :                                    \
        q==keyBytes ? (bits)/8 :                                \
        q==keyschedBytes ? ((bits)/32+6+1)*16 :                 \
        0)

#if !defined(NI_AES) || NI_AES == NI_NEVER
#define xAES(bits,q) (                                          \
        q==EncFunc ? (IntPtr)AES##bits##_Cipher :               \
        q==DecFunc ? (IntPtr)AES##bits##_InvCipher :            \
        q==KschdFunc ? (IntPtr)AES##bits##_KeyExpansion :       \
        cAES(bits,q) )

#elif NI_AES == NI_ALWAYS
#define DEF_INC_FROM_NI
#define xAES(bits,q) (                                          \
        q==EncFunc ? (IntPtr)NI_AES##bits##_Cipher :            \
        q==DecFunc ? (IntPtr)NI_AES##bits##_InvCipher :         \
        q==KschdFunc ? (IntPtr)AES##bits##_KeyExpansion :       \
        cAES(bits,q) )

#elif NI_AES == NI_RUNTIME
#define DEF_INC_FROM_NI
extern int extern_ni_aes_conf;
#define ni_aes_conf extern_ni_aes_conf

#define xAES(bits,q) (                                          \
        q==EncFunc ? (ni_aes_conf ?                             \
                      (IntPtr)NI_AES##bits##_Cipher :           \
                      (IntPtr)   AES##bits##_Cipher ) :         \
        q==DecFunc ? (ni_aes_conf ?                             \
                      (IntPtr)NI_AES##bits##_InvCipher :        \
                      (IntPtr)   AES##bits##_InvCipher ) :      \
        q==KschdFunc ? (IntPtr)AES##bits##_KeyExpansion :       \
        cAES(bits,q) )
#endif /* NI_AES */

#define cAES128(q) cAES(128,q)
#define cAES192(q) cAES(192,q)
#define cAES256(q) cAES(256,q)

#define xAES128(q) xAES(128,q)
#define xAES192(q) xAES(192,q)
#define xAES256(q) xAES(256,q)

IntPtr iAES128(int q);
IntPtr iAES192(int q);
IntPtr iAES256(int q);

#endif /* MySuiteA_rijndael_h */
