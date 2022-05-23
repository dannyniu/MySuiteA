/* DannyNiu/NJF, 2018-02-07. Public Domain. */

#include "sponge.h"
#include "../0-exec/struct-delta.c.h"

void Sponge_Update(sponge_t *restrict s, void const *restrict data, size_t len)
{
    uint8_t const *buffer = data;
    uint8_t *state = DeltaAdd(s, sizeof(*s) + s->blksize * 0);

    if( !data && len )
    {
        // 2018-02-09: Old note, may be relevant in future.
        // Pads the block and invoke 1 permutation.
        // See cSHAKE[128|256]_Init.
        //
        // 2022-04-14:
        // The note proved relevant. Also that, the condition
        // for invoking the permutation had been changed to
        // adapt for the definition of "bytepad" function in
        // NIST-SP-800-185.
        //
        // 2022-05-23:
        // Linter reported that the ``&& s->filled'' condition
        // may cause dereferencing of null pointer. It's being removed.
        //
        s->filled = s->rate;
        len = 0;
        goto permute;
    }

    while(len)
    {
        state[s->filled++] ^= *(buffer++);
        len--;

        if( s->filled == s->rate ) {
        permute:
            s->permute(state, state);
            s->filled = 0;
        }
    }
}

void Sponge_Final(sponge_t *restrict s)
{
    uint8_t *state = DeltaAdd(s, sizeof(*s) + s->blksize * 0);

    if( s->finalized ) return;

    /* Padding the Message. */

    state[s->filled] ^= s->lopad;
    state[s->rate-1] ^= s->hipad;

    s->permute(state, state);
    s->filled = 0;

    /* Finalization Guard. */

    s->finalized = true;
}

void Sponge_Read(sponge_t *restrict s, void *restrict data, size_t len)
{
    uint8_t *ptr = data;
    uint8_t *state = DeltaAdd(s, sizeof(*s) + s->blksize * 0);

    while( len-- )
    {
        *(ptr++) = state[s->filled++];

        if( s->filled == s->rate ) {
            s->permute(state, state);
            s->filled = 0;
        }
    }
}

void Sponge_Save(sponge_t *restrict s)
{
    uint8_t *state = DeltaAdd(s, sizeof(*s) + s->blksize * 0);
    uint8_t *saved = DeltaAdd(s, sizeof(*s) + s->blksize * 1);
    size_t t;

    for(t=0; t<s->blksize; t++)
        saved[t] = state[t];
}

void Sponge_Restore(sponge_t *restrict s)
{
    uint8_t *state = DeltaAdd(s, sizeof(*s) + s->blksize * 0);
    uint8_t *saved = DeltaAdd(s, sizeof(*s) + s->blksize * 1);
    size_t t;

    for(t=0; t<s->blksize; t++)
        state[t] = saved[t];
}
