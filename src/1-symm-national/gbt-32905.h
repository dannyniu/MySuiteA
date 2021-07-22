/* DannyNiu/NJF, 2021-07-20. Public Domain. */

#ifndef MySuiteA_gbt_32905_h
#define MySuiteA_gbt_32905_h 1

#include "../mysuitea-common.h"

// Words in M are in big-endian.
// To be converted to host byte order inside compression functions. 
void compressfunc_sm3(uint32_t V[8], uint32_t const *restrict M);

#endif /* MySuiteA_gbt_32905_h */
