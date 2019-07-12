/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#ifndef MySuiteA_keccak_h
#define MySuiteA_keccak_h 1

// References: src/notes.txt: "SHA3/Keccak". 

#include "../mysuitea-common.h"

void KeccakF1600_Permute(const void *in, void *out);

#define _iKeccakF(b,q) (                                        \
        q==blockBytes ? b/8 :                                   \
        q==PermuteFunc ? (uintptr_t)KeccakF##b##_Permute :      \
        0 )
#define _iKeccakF1600(q) _iKeccakF(1600,q)

intptr_t iKeccakF1600(int q);

#endif /* MySuiteA_keccak_h */
