/* DannyNiu/NJF, 2024-10-22. Public Domain. */

#include "hash-funcs-set.h"

typedef struct {
    // First 128 bits of the hash over the empty string.
    uint64_t lo, hi;

    // BER representation of the OID, and its length.
    char *oid;
    size_t oidlen;
} hash_dgst_oid_row_t;

// terminated by an entry with NULL oid.
extern hash_dgst_oid_row_t *hash_dgst_oids;

// returns a non-negative index into hash_dgst_oids, or -1 on error.
int MsgHash_FindOID(hash_funcs_set_t *hfnx, void *hctx);
