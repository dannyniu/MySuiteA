/* DannyNiu/NJF, 2018-02-13. Public Domain. */

#ifndef MySuiteA_poly1305_h
#define MySuiteA_poly1305_h 1

#include "../mysuitea-common.h"

typedef uint32_t p1305bn_t[5];

// fixed-sized. 
typedef struct
{
    p1305bn_t   r, s, a;
}
poly1305_t;

void poly1305_init(poly1305_t *restrict poly1305, uint8_t key[32]);
void poly1305_1block(poly1305_t *restrict poly1305, const void *restrict data);
void poly1305_final(poly1305_t *restrict poly1305);

#endif /* MySuiteA_poly1305_h */
