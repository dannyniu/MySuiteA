/* DannyNiu/NJF, 2023-09-02. Public Domain. */

#ifndef MySuiteA_M256_H
#define MySuiteA_M256_H 1

#include "../mysuitea-common.h"

typedef struct {
    int32_t r[256];
} module256_t;

#define SIZEOF_M256 sizeof(module256_t)

#endif /* MySuiteA_M256_H */
