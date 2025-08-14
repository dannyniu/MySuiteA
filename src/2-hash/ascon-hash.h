/* DannyNiu/NJF, 2025-01-28. Public Domain. */

#ifndef MySuiteA_ascon_hash_h
#define MySuiteA_ascon_hash_h 1

#include "../1-symm/ascon-permutation.h"
#include "../1-symm/sponge.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: Error | 8 *13 | 8 *14
typedef struct {
    sponge_t    sponge;
    union {
        uint8_t     u8[40];
        uint64_t    u64[5];
    } state[2];
} ascon_hash256_t;

void Ascon_Hash256_Init(ascon_hash256_t *restrict x);

void Ascon_Hash256_Update(
    ascon_hash256_t *restrict x, void const *restrict data, size_t len);

void Ascon_Hash256_Final(
    ascon_hash256_t *restrict x, void *restrict out, size_t t);

#define cAscon_Hash256(q) (                             \
        q==outBytes ? 32 :                              \
        q==blockBytes ? 8 :                             \
        q==contextBytes ? sizeof(ascon_hash256_t) :     \
        0)

#define xAscon_Hash256(q) (                             \
        q==InitFunc   ? (IntPtr)Ascon_Hash256_Init :    \
        q==UpdateFunc ? (IntPtr)Ascon_Hash256_Update :  \
        q==FinalFunc  ? (IntPtr)Ascon_Hash256_Final :   \
        cAscon_Hash256(q) )

IntPtr iAscon_Hash256(int q);

#endif /* MySuiteA_ascon_hash_h */
