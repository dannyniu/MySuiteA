/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#include "ecdsa.h"
#include "../2-hash/sha.h"

typedef struct {
    ECDSA_Priv_Ctx_Hdr_t x_hdr;
    union {
        sha256_t sha256;
        sha384_t sha384;
    };
} ECDSA_Priv_Ctx_t;
