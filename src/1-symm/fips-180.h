/* DannyNiu/NJF, 2018-02-05. Public Domain. */

#ifndef MySuiteA_fips_180_h
#define MySuiteA_fips_180_h 1

#include "../mysuitea-common.h"

// Words in M are in big-endian.
// To be converted to host byte order inside compression functions.
void compressfunc_sha1_ci(uint32_t H[5], uint32_t const *restrict M);
void compressfunc_sha256_ci(uint32_t H[8], uint32_t const *restrict M);
void compressfunc_sha512_ci(uint64_t H[8], uint64_t const *restrict M);

void compressfunc_sha1_ni(uint32_t H[5], uint32_t const *restrict M);
void compressfunc_sha256_ni(uint32_t H[8], uint32_t const *restrict M);
void compressfunc_sha512_ni(uint64_t H[8], uint64_t const *restrict M);

#if !defined(NI_FIPS180) || NI_FIPS180 == NI_NEVER
#define compressfunc_sha1 compressfunc_sha1_ci
#define compressfunc_sha256 compressfunc_sha256_ci
#define compressfunc_sha512 compressfunc_sha512_ci

#elif NI_FIPS180 == NI_ALWAYS
#define DEF_INC_FROM_NI
#define compressfunc_sha1 compressfunc_sha1_ni
#define compressfunc_sha256 compressfunc_sha256_ni
#define compressfunc_sha512 compressfunc_sha512_ni

#elif NI_FIPS180 == NI_RUNTIME
#define DEF_INC_FROM_NI
extern int extern_ni_fips180_conf;
#define ni_fips180_conf extern_ni_fips180_conf

#define compressfunc_sha1                       \
    ( ni_fips180_conf ?                         \
      compressfunc_sha1_ni :                    \
      compressfunc_sha1_ci )

#define compressfunc_sha256                     \
    ( ni_fips180_conf ?                         \
      compressfunc_sha256_ni :                  \
      compressfunc_sha256_ci )

#define compressfunc_sha512                     \
    ( ni_fips180_conf ?                         \
      compressfunc_sha512_ni :                  \
      compressfunc_sha512_ci )

#endif /* NI_FIPS180 */

#endif /* MySuiteA_fips_180_h */
