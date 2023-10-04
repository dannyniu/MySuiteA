/* DannyNiu/NJF, 2023-09-02. Public Domain. */

#ifndef MySuiteA_m256_codec_h
#define MySuiteA_m256_codec_h 1

#include "m256.h"

// 2023-09-02:
// The *U functions doesn't do sign conversion.
// The *S functions preserves the sign of operands.
// 'U' stands for "unsigned", 'S' stands for "short" and "signed"
// signifying that the coefficients of the polynomial is not in
// the full range of [0,q) or [{q-1)/2,{q-1}/2].

void *Module256EncU(
    uint8_t *restrict ptr, size_t len,
    module256_t const *restrict melem,
    int coeffbits);

void *Module256EncS( // Isn't used and isn't useful. Consider remove.
    uint8_t *restrict ptr, size_t len,
    module256_t const *restrict melem,
    int coeffbits, int32_t shift);

void *Module256DecU(
    uint8_t const *restrict ptr, size_t len,
    module256_t *restrict melem,
    int coeffbits);

void *Module256DecS( // Limited use. Keep.
    uint8_t const *restrict ptr, size_t len,
    module256_t *restrict melem,
    int coeffbits, int32_t shift);

#ifdef ENABLE_HOSTED_HEADERS

int melem_dump_dec(module256_t *melem);
int melem_dump_hex(module256_t *melem);
int melem_dump_hashed(module256_t *melem, char *msg, int r, int s);

#endif /* ENABLE_HOSTED_HEADERS */

#endif /* MySuiteA_m256_codec_h */
