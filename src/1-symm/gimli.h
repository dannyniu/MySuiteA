/* DannyNiu/NJF, 2018-04-20. Public Domain. */

#ifndef MySuiteA_gimli_h
#define MySuiteA_gimli_h 1

#include "../mysuitea-common.h"

void Gimli_Permute(void const *in, void *out);

#define cGimli(q) (                                     \
        q==blockBytes ? 48 :                            \
        q==PermuteFunc ? (uparam_t)Gimli_Permute :      \
        0 )

uparam_t iGimli(int q);

#endif /* MySuiteA_gimli_h */
