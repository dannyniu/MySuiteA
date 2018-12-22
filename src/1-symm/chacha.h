/* DannyNiu/NJF, 2018-02-16. Public Domain. */

#ifndef MySuiteA_chacha_h
#define MySuiteA_chacha_h 1

#include "../mysuitea-common.h"

// char:    8-bit,
// short:   16-bit,
// word:    32-bit,
// long;    64-bit. 

void chacha_word_set_state(void *restrict state,
                           const void *restrict key,
                           const void *restrict nonce);

void chacha_word_block(uint32_t *restrict state, uint32_t counter, 
                       size_t len, const void *in, void *out);

#endif /* MySuiteA_chacha_h */
