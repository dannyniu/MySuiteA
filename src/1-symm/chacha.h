/* DannyNiu/NJF, 2018-02-16. Public Domain. */

#ifndef MySuiteA_chacha_h
#define MySuiteA_chacha_h 1

#include "../mysuitea-common.h"

void chacha20_set_state(void *restrict state,
                           const void *restrict key,
                           const void *restrict nonce);

void chacha20_block(uint32_t *restrict state, uint32_t counter, 
                       size_t len, const void *in, void *out);

void blake2s_compress(uint32_t *restrict h, const void *m, uint64_t t, int f);
void blake2b_compress(uint64_t *restrict h, const void *m, uint64_t t, int f);

#endif /* MySuiteA_chacha_h */
