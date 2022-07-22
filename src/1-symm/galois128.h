/* DannyNiu/NJF, 2018-02-11. Public Domain. */

#include "../mysuitea-common.h"

void galois128_hash1block_ci(
    void *restrict Y, // Accumulator.
    void const *restrict H, // Hashing Key.
    void const *restrict X); // message block.

// declared but not defined if target platform doesn't support it.
void galois128_hash1block_ni(
    void *restrict Y, // Accumulator.
    void const *restrict H, // Hashing Key.
    void const *restrict X); // message block.

#if !defined(NI_GALOIS128) || NI_AES == NI_NEVER
#define galois128_hash1block galois128_hash1block_ci

#elif NI_GALOIS128 == NI_ALWAYS
#define galois128_hash1block galois128_hash1block_ni

#elif NI_GALOIS128 == NI_RUNTIME
extern int extern_ni_galois128_conf;
#define ni_galois128_conf extern_ni_galois128_conf;

#define galois128_hash1block                    \
    ( ni_galois128_conf ?                       \
      galois128_hash1block_ni :                 \
      galois128_hash1block_ci )
#endif /* NI_GALOIS128 */
