/* DannyNiu/NJF, 2018-02-05. Public Domain. */

#ifndef MySuiteA_fips_180_h
#define MySuiteA_fips_180_h 1

// References: src/notes.txt: "SHA-1, SHA-256, etc.". 

#include "../mysuitea-common.h"

// Words in M are in big-endian.
// To be converted inside compression functions. 
void compressfunc_sha1(uint32_t H[5], uint32_t const *restrict M);
void compressfunc_sha256(uint32_t H[8], uint32_t const *restrict M);
void compressfunc_sha512(uint64_t H[8], uint64_t const *restrict M);

#endif /* MySuiteA_fips_180_h */
