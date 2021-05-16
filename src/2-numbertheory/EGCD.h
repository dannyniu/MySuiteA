/* DannyNiu/NJF, 2021-05-15. Public Domain. */

#ifndef MySuiteA_EGCD_h
#define MySuiteA_EGCD_h 1

#include "../mysuitea-common.h"
#include "../1-integers/vlong.h"

// Returns y1 or y2 congruent to x^{-1} mod p,
// Returns NULL if gcd(x,p) != 1.
//
// The returned value may be negative in 2's complement representation
// and should be "normalized" with the function ``vlong_imod_inplace''.
//
// All arguments may be modified.
// Caller should ensure all arguments dereference to vlongs of same width.
//
vlong_t *EGCD(
    vlong_t *restrict x,
    vlong_t *restrict p,
    vlong_t *restrict quo,
    vlong_t *restrict rem,
    vlong_t *restrict y1,
    vlong_t *restrict y2);

#endif /* MySuiteA_EGCD_h */
