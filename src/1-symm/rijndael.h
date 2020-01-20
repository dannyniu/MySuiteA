/* DannyNiu/NJF, 2018-01-31. Public Domain. */

#ifndef MySuiteA_rijndael_h
#define MySuiteA_rijndael_h 1

#include "../mysuitea-common.h"

void AES128_Cipher(const void *in, void *out, const void *restrict w);
void AES192_Cipher(const void *in, void *out, const void *restrict w);
void AES256_Cipher(const void *in, void *out, const void *restrict w);

void AES128_InvCipher(const void *in, void *out, const void *restrict w);
void AES192_InvCipher(const void *in, void *out, const void *restrict w);
void AES256_InvCipher(const void *in, void *out, const void *restrict w);

void AES128_KeyExpansion(const void *restrict key, void *restrict w);
void AES192_KeyExpansion(const void *restrict key, void *restrict w);
void AES256_KeyExpansion(const void *restrict key, void *restrict w);

#define cAES(bits,q) (                                          \
        q==blockBytes ? 16 :                                    \
        q==keyBytes ? (bits)/8 :                                \
        q==keyschedBytes ? ((bits)/32+6+1)*16 :                 \
        q==EncFunc ? (uintptr_t)AES##bits##_Cipher :            \
        q==DecFunc ? (uintptr_t)AES##bits##_InvCipher :         \
        q==KschdFunc ? (uintptr_t)AES##bits##_KeyExpansion :    \
        0)
#define cAES128(q) cAES(128,q)
#define cAES192(q) cAES(192,q)
#define cAES256(q) cAES(256,q)

uintptr_t iAES128(int q);
uintptr_t iAES192(int q);
uintptr_t iAES256(int q);

#endif /* MySuiteA_rijndael_h */
