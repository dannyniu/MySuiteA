/* DannyNiu/NJF, 2018-03-01. Public Domain. */

#ifndef MySuiteA_bigint_h
#define MySuiteA_bigint_h 1

#include "bignum.h"

#define define_egcd_t(bits)                     \
    typedef struct {                            \
        bn_t          *ijr[4];                  \
        bn_t          *yyy[4];                  \
        bn##bits##_t  ijr_data[4];              \
        bn##bits##_t  yyy_data[4];              \
    } egcd##bits##_t;

inst_type_bits(define_egcd_t)

#define EGCD_SETUP(egcd) (                              \
        (egcd)->ijr[0] = (bn_t *)&(egcd)->ijr_data[0],  \
        (egcd)->ijr[1] = (bn_t *)&(egcd)->ijr_data[1],  \
        (egcd)->ijr[2] = (bn_t *)&(egcd)->ijr_data[2],  \
        (egcd)->ijr[3] = (bn_t *)&(egcd)->ijr_data[3],  \
        (egcd)->yyy[0] = (bn_t *)&(egcd)->yyy_data[0],  \
        (egcd)->yyy[1] = (bn_t *)&(egcd)->yyy_data[1],  \
        (egcd)->yyy[2] = (bn_t *)&(egcd)->yyy_data[2],  \
        (egcd)->yyy[3] = (bn_t *)&(egcd)->yyy_data[3],  \
        0)

typedef union {
    // see also notes in bn_t. 
    decl_union_members(egcd)
    struct {
        bn_t      *ijr[4];
        bn_t      *yyy[4];
    };
} egcd_t;

void bn_egcd(long n, egcd_t *restrict egcd, bn_t *out, const bn_t *a, const bn_t *p);

#define define_mont_t(bits)                     \
    typedef struct {                            \
        long  logR_base32;                      \
        bn_t  *R_inv, *N_apos, *N, *m, *t;      \
        bn##bits##_t data[5];                   \
    } mont##bits##_t;

inst_type_bits(define_mont_t)

#define MONT_SETUP(mont) (                              \
        (mont)->R_inv  = (bn_t *)&(mont)->data[0],      \
        (mont)->N_apos = (bn_t *)&(mont)->data[1],      \
        (mont)->N      = (bn_t *)&(mont)->data[2],      \
        (mont)->m      = (bn_t *)&(mont)->data[3],      \
        (mont)->t      = (bn_t *)&(mont)->data[4],      \
        0)

typedef union {
    // see also notes in bn_t.
    decl_union_members(mont)
    struct {
        long      logR_base32;
        bn_t      *R_inv, *N_apos, *N, *m, *t;
    };
} mont_t;

void bn_mont_set_N(long n, mont_t *restrict mont, egcd_t *restrict egcd, const bn_t *N);
void bn_mont_convert(long n, mont_t *restrict mont, bn_t *out, const bn_t *a);
void bn_mont_REDC(long n, mont_t *restrict mont, bn_t *out, const bn_t *T);

void bn_mont_modexp(long n, mont_t *restrict mont,
                    bn_t *out, // in Montgomery form. 
                    const bn_t *restrict b, // in Montgomery form. 
                    const bn_t *restrict e, // in normal form.
                    bn_t *restrict tmp);

#endif /* MySuiteA_bigint_h */
