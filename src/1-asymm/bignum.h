/* DannyNiu/NJF, 2018-03-01. Public Domain. */

#ifndef MySuiteA_bignum_h
#define MySuiteA_bignum_h 1

#include "../mysuitea-common.h"

#define define_bn_t(bits)                       \
    typedef struct {                            \
        uint32_t w[bits/32];                    \
    } bn##bits##_t;

define_bn_t(640)
define_bn_t(1280)
define_bn_t(6400)
define_bn_t(12800)

typedef union {
    // this type is only used for casting pointers,
    // no actual data should be held in this union type. 
    bn640_t     bn640;
    bn1280_t    bn1280;
    bn6400_t    bn6400;
    bn12800_t   bn12800;
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
