/* DannyNiu/NJF, 2021-07-20. Public Domain. */

#ifndef MySuiteA_gbt_32905_h
#define MySuiteA_gbt_32905_h 1

#include "../mysuitea-common.h"

// Words in M are in big-endian.
// To be converted to host byte order inside compression functions.
void compressfunc_sm3_ci(uint32_t V[8], uint32_t const *restrict M);
void compressfunc_sm3_ni(uint32_t V[8], uint32_t const *restrict M);

#if !defined(NI_SM3) || NI_SM3 == NI_NEVER
#define compressfunc_sm3 compressfunc_sm3_ci

#elif NI_SM3 == NI_ALWAYS
#define DEF_INC_FROM_NI
#define compressfunc_sm3 compressfunc_sm3_ni

#elif NI_SM3 == NI_RUNTIME
#define DEF_INC_FROM_NI
extern int extern_ni_sm3_conf;
#define ni_sm3_conf extern_ni_sm3_conf

#define compressfunc_sm3                        \
    ( ni_sm3_conf ?                             \
      compressfunc_sm3_ni :                     \
      compressfunc_sm3_ci )

#endif /* NI_SM3 */

#endif /* MySuiteA_gbt_32905_h */
