/* DannyNiu/NJF, 2023-09-02. Public Domain. */

#ifndef MySuiteA_Dilithium_Aux_H
#define MySuiteA_Dilithium_Aux_H 1

#include "../1-pq-crystals/m256.h"

#define MLDSA_Q 8380417
#define MLDSA_D 13

void MLDSA_RejNTTPoly(
    module256_t *restrict melem,
    uint8_t const rho[restrict 32],
    int s, int r);

void MLDSA_RejBoundedPoly_TRNG(
    module256_t *restrict melem,
    GenFunc_t prng_gen, void *restrict prng, int eta);

void MLDSA_RejBoundedPoly(
    module256_t *restrict melem,
    uint8_t const rho[restrict 64],
    int r, int eta);

void MLDSA_ExpandMask_1Poly_TRNG(
    module256_t *restrict melem,
    GenFunc_t prng_gen, void *restrict prng,
    int l2gamma);

void MLDSA_ExpandMask_1Poly(
    module256_t *restrict melem,
    uint8_t const rho[restrict 64],
    int r, int l2gamma, int kappa);

int64_t MLDSA_UModQ(int64_t r); // unsigned modular reduction.

module256_t *MLDSA_Add(
    module256_t *c,
    module256_t *a,
    module256_t *b,
    int accum);

module256_t *MLDSA_Sub(
    module256_t *c,
    module256_t *a,
    module256_t *b);

module256_t *MLDSA_NttScl(
    module256_t *c,
    module256_t *a,
    module256_t *b,
    int accum);

bool MLDSA_HasOverflow(module256_t *m, int32_t bound);

int32_t MLDSA_Power2Round(int32_t r, int32_t *r0_out, int d);
int32_t MLDSA_Decompose(int32_t r, int32_t *r0_out, int32_t gamma2);

int MLDSA_MakeHint(int32_t z, int32_t r, int32_t gamma2);
int32_t MLDSA_UseHint(int32_t r, int h, int32_t gamma2);

void MLDSA_NTT(module256_t *restrict melem);
void MLDSA_InvNTT(module256_t *restrict melem);

int32_t MLDSA_Decompose_Logging(int32_t r, int32_t *r0_out, int32_t gamma2);
bool MLDSA_HasOverflow_Logging(module256_t *m, int32_t bound);
#endif /* MySuiteA_Dilithium_Aux_H */
