/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#include "keccak.h"

#define Keccak_StateSize 1600
#define keccak_word_t uint64_t
#include "keccak.c.h"

#if NI_KECCAK == NI_RUNTIME
int extern_ni_keccak_conf;
#endif /* NI_KECCAK */
