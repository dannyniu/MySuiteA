/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#ifndef MySuiteA_hash_funcs_set_h
#define MySuiteA_hash_funcs_set_h 1

#include "../mysuitea-common.h"

// Definition for common data structure(s) for hash functions used in PKC.

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 2 * 4 | 4 * 4 | 8 * 4
typedef struct {
    InitFunc_t          initfunc;
    UpdateFunc_t        updatefunc;
    XFinalFunc_t        xfinalfunc;
    FinalFunc_t         hfinalfunc;
} hash_funcs_set_t;

#define HASH_FUNCS_SET_INIT(hash)               \
    ((hash_funcs_set_t){                        \
        .initfunc = INIT_FUNC(hash),            \
        .updatefunc = UPDATE_FUNC(hash),        \
        .xfinalfunc = XFINAL_FUNC(hash),        \
        .hfinalfunc = XFINAL_FUNC(hash) ?       \
        READ_FUNC(hash) : FINAL_FUNC(hash),     \
    })

#endif /* MySuiteA_hash_funcs_set_h */
