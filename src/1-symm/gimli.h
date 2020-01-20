/* DannyNiu/NJF, 2018-04-20. Public Domain. */

#ifndef MySuiteA_gimli_h
#define MySuiteA_gimli_h 1

// References: src/notes.txt: "Gimli".

#include "../mysuitea-common.h"

void Gimli_Permute(const void *in, void *out);

#define cGimli(q) (                                     \
        q==blockBytes ? 48 :                            \
        q==PermuteFunc ? (uintptr_t)Gimli_Permute :     \
        0 )

uintptr_t iGimli(int q);

#endif /* MySuiteA_gimli_h */
