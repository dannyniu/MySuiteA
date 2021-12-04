/* DannyNiu/NJF, 2021-09-03. Public Domain. */
// VLong - Octet String conversion.

#ifndef MySuiteA_vlong_dat_h
#define MySuiteA_vlong_dat_h 1

#include "vlong.h"

static_assert(sizeof(uint32_t) == 4, "Data type assumption failed.");

vlong_size_t vlong_topbit(vlong_t *x);

void vlong_OS2IP(vlong_t *restrict vl, const uint8_t *restrict os, size_t len);
void vlong_I2OSP(vlong_t const *restrict vl, uint8_t *restrict os, size_t len);

#endif /* MySuiteA_vlong_dat_h */
