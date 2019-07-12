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

#define _iAES(bits,q) (                                         \
        q==blockBytes ? 16 :                                    \
        q==keyBytes ? (bits)/8 :                                \
        q==keyschedBytes ? ((bits)/32+6+1)*16 :                 \
        q==EncFunc ? (uintptr_t)AES##bits##_Cipher :            \
        q==DecFunc ? (uintptr_t)AES##bits##_InvCipher :         \
        q==KschdFunc ? (uintptr_t)AES##bits##_KeyExpansion :    \
        0)
#define _iAES128(q) _iAES(128,q)
#define _iAES192(q) _iAES(192,q)
#define _iAES256(q) _iAES(256,q)

uintptr_t iAES128(int q);
uintptr_t iAES192(int q);
uintptr_t iAES256(int q);

#endif /* MySuiteA_rijndael_h */
