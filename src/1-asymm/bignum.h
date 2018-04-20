/* DannyNiu/NJF, 2018-03-01. Public Domain. */

#ifndef MySuiteA_bignum_h
#define MySuiteA_bignum_h 1

#include "../mysuitea-common.h"

// The following two macros are the configuration for
// default big integer sizes for number-theory working types.
// Since they're common alone side bn_t, it's defined along side it. 

#define inst_type_bits(definer)                 \
    definer(1600)                               \
    definer(6400)                               \
    definer(16000)

#define decl_union_members(prefix)              \
    prefix##1600##_t    prefix##1600;           \
    prefix##6400##_t    prefix##6400;           \
    prefix##16000##_t   prefix##16000;

// Defines bn_t template. 

#define define_bn_t(bits)                       \
    typedef struct {                            \
        uint32_t w[bits/32];                    \
    } bn##bits##_t;

// Defines bn*_t instances. 

inst_type_bits(define_bn_t)

typedef union {
    // this type is only used for casting pointers,
    // no actual data should be held in this union type. 
    decl_union_members(bn)
    uint32_t    w[0+1]; // just to be standard-conformant. 
} bn_t;

uint32_t bn_add(long n, bn_t *out, const bn_t *a, const bn_t *b, uint64_t x);
int32_t bn_sub(long n, bn_t *out, const bn_t *a, const bn_t *b, uint64_t x);
uint32_t bn_imul(long n, bn_t *out, const bn_t *a, uint64_t b);
uint32_t bn_idiv(long n, bn_t *out, const bn_t *a, uint64_t b);
void bn_mul(long n,
            bn_t *restrict out,
            const bn_t *a,
            const bn_t *b);
void bn_div(long n,
            bn_t *restrict quo, // optional. 
            bn_t *rem,         // mandatory. 
            const bn_t *a,
            const bn_t *restrict b);

#endif /* MySuiteA_bignum_h */
