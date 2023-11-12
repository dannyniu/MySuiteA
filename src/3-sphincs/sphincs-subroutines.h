/* DannyNiu/NJF, 2023-11-05. Public Domain. */

#ifndef MySuiteA_sphincs_subroutines_h
#define MySuiteA_sphincs_subroutines_h 1

#include "slhdsa.h"

typedef struct {
    uint32_t layeraddr;
    uint32_t treeaddr[3];
    uint32_t type;
    union {
        uint32_t t1;
        uint32_t keypairaddr;
    };
    union {
        uint32_t t2;
        uint32_t chainaddr;
        uint32_t treeheight;
    };
    union{
        uint32_t t3;
        uint32_t hashaddr;
        uint32_t treeindex;
    };
} SPHINCS_ADRS_t;

enum {
    WOTS_HASH = 0,
    WOTS_PK,
    TREE,
    FORS_TREE,
    FORS_ROOTS,
    WOTS_PRF,
    FORS_PRF,
};

void wots_PKgen(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen);

void wots_sign(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen);

void wots_PKFromSig(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen);

void xmss_auth_path_and_root_node(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen, // root node
    uint32_t idx, void *auth, size_t alen); // auth path.

void xmss_sign(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen, uint32_t idx);

void xmss_PKFromSig(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen, uint32_t idx);

void ht_sign(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen,
    uint32_t idx_tree[3], // in big-endian
    uint32_t idx_leaf); // in host-endian

bool ht_verify(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    uint32_t idx_tree[3], // in big-endian
    uint32_t idx_leaf); // in host-endian

void fors_sign(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen);

void fors_pkFromSig(
    SLHDSA_Ctx_Hdr_t *restrict x,
    bufvec_t *restrict in,
    void *out, size_t outlen);

#endif /* MySuiteA_sphincs_subroutines_h */
