/* DannyNiu/NJF, 2021-02-16. Public Domain. */

#ifndef MySuiteA_MillerRabin_h
#define MySuiteA_MillerRabin_h 1

#include "../mysuitea-common.h"
#include "../1-integers/vlong.h"

// returns 0 for composite, and 1 for probably prime.
int MillerRabin(
    vlong_t const *restrict w,
    int iterations,
    vlong_t *restrict tmp1, // temporary variables are
    vlong_t *restrict tmp2, // allocated by the caller
    vlong_t *restrict tmp,
    GenFunc_t rng, void *restrict rng_ctx);

#endif /* MySuiteA_MillerRabin_h */
