/* DannyNiu/NJF, 2018-03-31. Public Domain. */

#ifndef MySuiteA_rsa_common_h
#define MySuiteA_rsa_common_h 1

#include "../1-asymm/bigint.h"

#define define_rsa_t(bits)                                              \
    typedef struct {                                                    \
        long            n;                                              \
        egcd_t          *egcd;                                          \
        mont_t          *mont;                                          \
        bn_t            *e, *m, *c;                                     \
        egcd##bits##_t  egcd_data;                                      \
        mont##bits##_t  mont_data;                                      \
        bn##bits##_t    e_data, m_data, c_data;                         \
    } rsa##bits##_t; // reuse ''egcd'' variables for tmp in ''bn_mont_modexp''. 

inst_type_bits(define_rsa_t)

typedef union {
    decl_union_members(rsa)
    struct {
        long            n;
        egcd_t          *egcd;
        mont_t          *mont;
        bn_t            *e, *m, *c;
    };
} rsa_t;

#define RSA_SETUP(rsa) (                                \
        (rsa)->egcd = (egcd_t *)&(rsa)->egcd_data,      \
        (rsa)->mont = (mont_t *)&(rsa)->mont_data,      \
        (rsa)->e    = (bn_t   *)&(rsa)->e_data,         \
        (rsa)->m    = (bn_t   *)&(rsa)->m_data,         \
        (rsa)->c    = (bn_t   *)&(rsa)->c_data,         \
        EGCD_SETUP(&(rsa)->egcd_data),                  \
        MONT_SETUP(&(rsa)->mont_data),                  \
        0)

#endif /* MySuiteA_rsa_common_h */
