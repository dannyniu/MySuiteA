/* DannyNiu/NJF, 2018-02-13. Public Domain. */

#ifndef MySuiteA_poly1305_h
#define MySuiteA_poly1305_h 1

#include "../mysuitea-common.h"

typedef uint32_t p1305bn_t[5];

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:        4 * 15       .
typedef struct {
    p1305bn_t   r, s, a;
} poly1305_t;

// A bit of note here.
// poly1305_init is known to be used by ChaCha_AEAD_*
// with key set to a blob aligned to 64-bit boundary.
// So accordingly, the prototype is changed in order to silce a warning.
void poly1305_init(poly1305_t *restrict poly1305, void const *restrict key);

void poly1305_1block(poly1305_t *restrict poly1305, void const *restrict data);
void poly1305_final(poly1305_t *restrict poly1305);

#endif /* MySuiteA_poly1305_h */
