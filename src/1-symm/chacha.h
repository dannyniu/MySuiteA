/* DannyNiu/NJF, 2018-02-16. Public Domain. */

#ifndef MySuiteA_chacha_h
#define MySuiteA_chacha_h 1

#include "../mysuitea-common.h"

void chacha20_set_state(
    void *restrict state,
    void const *restrict key,
    void const *restrict nonce);

void chacha20_block(
    uint32_t *restrict state,
    uint32_t counter,
    size_t len, void const *in, void *out);

void blake2s_compress(uint32_t *restrict h, void const *m, uint64_t t, int f);
void blake2b_compress(uint64_t *restrict h, void const *m, uint64_t t, int f);

#endif /* MySuiteA_chacha_h */
