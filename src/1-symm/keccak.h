/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#ifndef MySuiteA_keccak_h
#define MySuiteA_keccak_h 1

#include "../mysuitea-common.h"

void KeccakP1600_Permute(void const *in, void *out, int rounds);
void KeccakF1600_Permute(void const *in, void *out);

#define cKeccakF(b,q) ( q==blockBytes ? b/8 : 0 )

#define xKeccakF(b,q) (                                 \
        q==PermuteFunc ? (IntPtr)KeccakF##b##_Permute : \
        cKeccakF(b,q) )

#define cKeccakF1600(q) cKeccakF(1600,q)
#define xKeccakF1600(q) xKeccakF(1600,q)

IntPtr iKeccakF1600(int q);

#endif /* MySuiteA_keccak_h */
