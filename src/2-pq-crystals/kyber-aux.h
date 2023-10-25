/* DannyNiu/NJF, 2023-10-23. Public Domain. */

#ifndef MySuiteA_Kyber_Aux_H
#define MySuiteA_Kyber_Aux_H 1

#include "../1-pq-crystals/m256.h"

#define MLKEM_Q 3329

void MLKEM_SampleNTT(
    module256_t *restrict melem,
    uint8_t const rho[restrict 32],
    int i, int j);

void MLKEM_SamplePolyCBD(
    module256_t *restrict melem,
    uint8_t const r[restrict 32],
    int n, int eta);

int32_t MLKEM_UModQ(int32_t r); // unsigned modular reduction.

module256_t *MLKEM_Add(
    module256_t *c,
    module256_t *a,
    module256_t *b,
    int accum);

module256_t *MLKEM_Sub(
    module256_t *c,
    module256_t *a,
    module256_t *b);

module256_t *MLKEM_NttScl(
    module256_t *c,
    module256_t *a,
    module256_t *b,
    int accum);

void MLKEM_Compress(module256_t *m, int d);
void MLKEM_Decompress(module256_t *m, int d);

void MLKEM_NTT(module256_t *restrict melem);
void MLKEM_InvNTT(module256_t *restrict melem);

#endif /* MySuiteA_Kyber_Aux_H */
