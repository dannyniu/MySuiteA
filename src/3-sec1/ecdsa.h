/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#ifndef MySuiteA_ecdsa_h
#define MySuiteA_ecdsa_h 1

#include "sec1-common.h"
#include "../2-hash/hash-funcs-set.h"

// ${ [0].* } are that for curve domain parameters.
// ${ [1].* } are that for the hash function.
typedef CryptoParam_t ECDSA_Param_t[2];

typedef SEC1_Hash_Ctx_Hdr_t ECDSA_Ctx_Hdr_t;

#define ECDSA_CTX_INIT_X(crv,hash) SEC1_CTX_INIT_X(     \
        ECDSA_Ctx_Hdr_t,                                \
        crv, hash,                                      \
        .hlen = hash(outBytes),                         \
        .hfuncs = HASH_FUNCS_SET_INIT(hash),            \
        .context_type = 2,                              \
        .offset_hashctx = sizeof(ECDSA_Ctx_Hdr_t))

#define ECDSA_CTX_INIT(...) ECDSA_CTX_INIT_X(__VA_ARGS__)

IntPtr ECDSA_Keygen(
    ECDSA_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

void *ECDSA_Sign(
    ECDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

void const *ECDSA_Verify(
    ECDSA_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen);

#endif /* MySuiteA_ecdsa_h */
