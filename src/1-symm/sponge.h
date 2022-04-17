/* DannyNiu/NJF, 2018-02-07. Public Domain. */

#ifndef MySuiteA_sponge_h
#define MySuiteA_sponge_h 1

#include "../mysuitea-common.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 2 * 6 | 4 * 6 | 8 * 4
typedef struct sponge {
    unsigned        rate;
    union {
        struct {
            uint8_t lopad, hipad;
        };
        int         struct_pad;
    };
    int             finalized;
    unsigned        filled;

    PermuteFunc_t   permute;

    // `blksize' is the block size of the permutation.
    // 2 blocks are directly appended to the sponge
    // working context - the 1st one is the one used in
    // absorb and squeeze phases, the 2nd one is used
    // for saving the "finalized" state after absorb
    // and before the squeeze phase. The value of this
    // member is used to calculate the offset (from the
    // beginning of the `sponge_t' struct) to the
    // permutation block.
    //
    // The state buffer is initialized by
    // functions or macros associated with
    // the structure that embeds `sponge_t'.
    //
    size_t          blksize;
} sponge_t;

#define SPONGE_INIT(r,lo,hi,p) ((sponge_t){             \
            .rate = r, .lopad = lo, .hipad = hi,        \
            .finalized = false, .filled = 0,            \
            .permute = PERMUTE_FUNC(p),                 \
            .blksize = BLOCK_BYTES(p),                  \
        })

void Sponge_Update(sponge_t *restrict s, void const *restrict data, size_t len);
void Sponge_Final(sponge_t *restrict s);
void Sponge_Read(sponge_t *restrict s, void *restrict data, size_t len);

// copies the content of the 1st state block to the 2nd.
void Sponge_Save(sponge_t *restrict s);

// copies the content of the 2nd state block back to the 1st.
void Sponge_Restore(sponge_t *restrict s);

#endif /* MySuiteA_sponge_h */
