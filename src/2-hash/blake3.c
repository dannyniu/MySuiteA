/* DannyNiu/NJF, 2022-08-17. Public Domain. */

#include "blake3.h"
#include "blake-common.c.h"
#include "../1-oslib/TCrew-common.h"
#include "../0-datum/endian.h"

#define CHUNK_START     (1 << 0)
#define CHUNK_END       (1 << 1)
#define PARENT          (1 << 2)
#define ROOT            (1 << 3)
#define KEYED_HASH      (1 << 4)
#define DERIVE_KEY_CONTEXT      (1 << 5)
#define DERIVE_KEY_MATERIAL     (1 << 6)

static void init1node(blake3_node_t *restrict node, int64_t id)
{
    uint16_t i;
    
    blake3_t *x;
    char *ptr = (void *)node;
    ptr -= offsetof(blake3_t, nodes[id]);
    x = (void *)ptr;

    node->hashed = false;
    node->height = 0;
    node->remain = 0;
    node->d = x->keyed ? KEYED_HASH : 0;
    node->me = id;
    for(i=0; i<256; i++) node->buf.u32[i] = 0;
}

void BLAKE3_Init(blake3_t *x)
{
    int i;

    for(i=0; i<8; i++) x->k.u32[i] = 0;

    x->t = 0;
    x->keyed = false;
    x->finalize = false;
    x->leaves_filled = 0;
    x->branches_filled = 0;

    for(i=0; i<BLAKE3_NODES_COUNT; i++)
    {
        x->nind[i] = i;
        init1node(x->nodes+i, i);
    }
}

blake3_t *BLAKE3_KInit(blake3_t *x, const void *k, size_t klen)
{
    int i;

    if( klen != 32 ) return NULL;

    for(i=0; i<32; i++) x->k.u8[i] = ((uint8_t *)k)[i];

    x->t = 0;
    x->keyed = true;
    x->finalize = false;
    x->leaves_filled = 0;
    x->branches_filled = 0;

    for(i=0; i<BLAKE3_NODES_COUNT; i++)
    {
        x->nind[i] = i;
        init1node(x->nodes+i, i);
    }

    return x;
}

#define msg(i) ( m ? m[s[i]] : 0 )

static inline void
inner_block_word(uint32_t state[16], uint32_t const m[16], uint8_t const s[16])
{
    qround_word(state[ 0], state[ 4], state[ 8], state[12], msg( 0), msg( 1));
    qround_word(state[ 1], state[ 5], state[ 9], state[13], msg( 2), msg( 3));
    qround_word(state[ 2], state[ 6], state[10], state[14], msg( 4), msg( 5));
    qround_word(state[ 3], state[ 7], state[11], state[15], msg( 6), msg( 7));

    qround_word(state[ 0], state[ 5], state[10], state[15], msg( 8), msg( 9));
    qround_word(state[ 1], state[ 6], state[11], state[12], msg(10), msg(11));
    qround_word(state[ 2], state[ 7], state[ 8], state[13], msg(12), msg(13));
    qround_word(state[ 3], state[ 4], state[ 9], state[14], msg(14), msg(15));
}

static void
blake3_compress(
    uint32_t h[restrict 16], // host-endian.
    uint32_t const m[restrict 16], // little-endian.
    uint64_t t, uint32_t b, uint32_t d)
{
    int i, j;
    uint32_t v[16];

    static const uint8_t tab[16] = {
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };

    uint8_t lut[16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    uint8_t bak[16];

    for(i=0; i<8; i++) v[i] = h[i];
    v[ 8] = IV0;
    v[ 9] = IV1;
    v[10] = IV2;
    v[11] = IV3;
    v[12] = t;
    v[13] = t>>32;
    v[14] = b;
    v[15] = d;

    for(i=0; i<7; i++)
    {
        inner_block_word(v, m, lut);
        for(j=0; j<16; j++) bak[j] = tab[lut[j]];
        for(j=0; j<16; j++) lut[j] = bak[j];
    }

    for(i=0; i<8; i++)
    {
        h[i+8] = h[i] ^ v[i+8];
        h[i+0] = v[i] ^ v[i+8];
    }
}

static void hash1node(blake3_t *restrict x, blake3_node_t *restrict node)
{
    uint32_t h[16] = { // will change when supporting keyed hashing.
        IV0, IV1, IV2, IV3,
        IV4, IV5, IV6, IV7,
    };
    long t;

    if( x->keyed )
    {
        for(t=0; t<8; t++)
            h[t] = le32toh(x->k.u32[t]);
    }

    for(t=0; t<16; t++)
    {
        uint32_t d = node->d;
        uint32_t b = 64;

        if( t == 0 && node->height == 0 ) d |= CHUNK_START;
        if( node->height > 0 ) d |= PARENT;
        if( node->remain < b ) b = node->remain;

        if( node->remain <= 64 )
        {
            if( node->height == 0 ) d |= CHUNK_END;
            if( x->finalize )
            {
                node->remain += t * 64; // must come before.
                node->d = d |= ROOT;

                for(t=0; t<8; t++) // because ``t'' is overwritten here.
                    x->k.u32[t] = h[t];

                goto finish;
            }
        }

        blake3_compress(h, &node->buf.u32[t * 16], node->t, b, d);
        node->remain -= b;

        if( node->remain == 0 ) break;
    }

    for(t=0; t<16; t++)
        node->buf.u32[t] = htole32(h[t]);

finish:
    return;
}

static void chunk2leaf(blake3_t *restrict x, blake3_node_t *restrict node)
{
    hash1node(x, node);
    node->hashed = true;
    node->height = 0;
}

static void bury1node(blake3_t *restrict x, int ni)
{
    int i;
    int sv;
    assert(ni < BLAKE3_NODES_COUNT);

    sv = x->nind[ni];

    for(i=ni; i+1<BLAKE3_NODES_COUNT; i++)
        x->nind[i] = x->nind[i+1];

    x->nind[BLAKE3_NODES_COUNT-1] = sv;
}

static void join2nodes(blake3_t *restrict x, int li)
{
    int i;
    blake3_node_t *node1, *node2;
    node1 = x->nodes + x->nind[li + 0];
    node2 = x->nodes + x->nind[li + 1];

    for(i=0; i<8; i++)
    {
        node1->buf.u32[i+8] = node2->buf.u32[i]; // ident-endian-copy.
    }

    node1->t = 0;
    node1->d = x->keyed ? KEYED_HASH : 0; // was: node1->d = 0;
    node1->remain = 64;
    node1->hashed = false;
    node1->height ++;
}

static void commit1parent(blake3_t *restrict x, blake3_node_t *restrict node)
{
    hash1node(x, node);
    node->hashed = true;
}

static void job_hash1leaf(blake3_node_t *node)
{
    blake3_t *x;
    char *ptr = (void *)node;
    ptr -= offsetof(blake3_t, nodes[node->me]);
    x = (void *)ptr;

    chunk2leaf(x, node);
}

size_t update_fill(
    blake3_t *restrict x,
    uint8_t const *restrict inPtr,
    size_t inLen)
{
    uint8_t const *start = inPtr;
    int i;

    i = x->branches_filled + x->leaves_filled;
    while( i<BLAKE3_NODES_COUNT && inLen )
    {
        blake3_node_t *node = x->nodes + x->nind[i];
        assert( !node->hashed && node->height == 0 );
        assert( node->remain <= 1024 );

        if( node->remain == 1024 )
        {
            // only after the next leaf is ready.
            node->t = x->t++;
            x->leaves_filled++;
            i++;
            continue;
        }

        while( node->remain < 1024 )
        {
            node->buf.u8[node->remain++] = *inPtr++;
            if( --inLen == 0 ) break;
        }
    }

    return (size_t)(inPtr - start);
}

static void update_climb(blake3_t *x)
{
    int i;
    blake3_node_t *node1, *node2;

    x->branches_filled += x->leaves_filled;
    x->leaves_filled = 0;

    i = 0;
    while( i + 1 < x->branches_filled )
    {
        node1 = x->nodes + x->nind[i+0];
        node2 = x->nodes + x->nind[i+1];

        if( node1->height == node2->height )
        {
            if( !node1->hashed ) commit1parent(x, node1);
            if( !node2->hashed ) commit1parent(x, node2);
            
            join2nodes(x, i);
            init1node(node2, node2->me);
            bury1node(x, i+1);

            if( i > 0 || x->branches_filled > 2 )
                commit1parent(x, node1);

            x->branches_filled--;
            i = 0;
            continue;
        }
        else
        {
            ++i;
            continue;
        }
    }

    return;
}

static void update_1bat2tc(
    blake3_t *restrict x,
    TCrew_Abstract_t *restrict tc)
{
    int i;

    i = x->branches_filled;
    for(; i < x->branches_filled + x->leaves_filled; i++)
    {
        blake3_node_t *node = x->nodes + x->nind[i];
        assert( !node->hashed && node->height == 0 );
        assert( node->remain <= 1024 );

        if( node->remain == 1024 )
            tc->enqueue(tc, (TCrew_Assignment_t)job_hash1leaf, node);
        else break; // not a filled leaf. won't (shoudn't) reach.
    }

    tc->wait(tc, (TCrew_Assignment_t)update_climb, x);
}

void BLAKE3_Update4(
    blake3_t *restrict x,
    void const *restrict dat,
    size_t len,
    TCrew_Abstract_t *restrict tc)
{
    size_t subret = 0;
    uint8_t const *ptr = dat;

    do
    {
        subret = update_fill(x, ptr, len);
        update_1bat2tc(x, tc);

        ptr += subret;
        len -= subret;
    }
    while( subret > 0 );
}

static void final_climb(blake3_t *x)
{
    int i;
    blake3_node_t *node1, *node2;

    update_climb(x); // process sibling nodes and leaves.

    // merge branches from lowest hight to the highest.
    i = x->branches_filled - 1;

    while( --i > 0 )
    {
        node1 = x->nodes + x->nind[i+0];
        node2 = x->nodes + x->nind[i+1];

        if( !node1->hashed ) commit1parent(x, node1);
        if( !node2->hashed ) commit1parent(x, node2);

        join2nodes(x, i);
        init1node(node2, node2->me);
        bury1node(x, i+1);
        commit1parent(x, node1);
        x->branches_filled--;
    }

    // at this point, there should be no more than 2 un-merged branches.
    assert( x->branches_filled <= 2 );

    if( x->branches_filled == 2 )
    {
        node1 = x->nodes + x->nind[0];
        node2 = x->nodes + x->nind[1];

        if( !node1->hashed ) commit1parent(x, node1);
        if( !node2->hashed ) commit1parent(x, node2);

        join2nodes(x, 0);
        init1node(node2, node2->me);
        bury1node(x, 1);
    }

    node1 = x->nodes + x->nind[0];
    if( !node1->hashed )
    {
        // finalize will be set only on 2 (3?) occasions.
        // the one here is when there are
        // at least 2 chunks in the message.
        x->finalize = true;
        commit1parent(x, node1);
        x->branches_filled--;
    }

    return;
}

void final_1bat2tc(
    blake3_t *restrict x,
    TCrew_Abstract_t *restrict tc)
{
    int i;

    i = x->branches_filled;
    for(; i < BLAKE3_NODES_COUNT; i++)
    {
        blake3_node_t *node = x->nodes + x->nind[i];
        assert( !node->hashed && node->height == 0 );
        assert( node->remain <= 1024 );

        if( node->remain == 0 && i > 0 )
        {
            break;
            // continue should do the same.
        }

        if( node->remain <= 1024 &&
            x->branches_filled == 0 &&
            x->leaves_filled == 0 )
        {
            // finalize will be set only on 2 (3?) occasions.
            // this last one here is when there's
            // only 1 chunk in the entire message..
            x->finalize = true;
        }

        node->t = x->t++;
        x->leaves_filled++;

        tc->enqueue(tc, (TCrew_Assignment_t)job_hash1leaf, node);
    }

    tc->wait(tc, (TCrew_Assignment_t)final_climb, x);
}

void BLAKE3_Final2(blake3_t *restrict x, TCrew_Abstract_t *restrict tc)
{
    if( !x->finalize )
    {
        final_1bat2tc(x, tc); // will set ``x->finalize''
        x->t = 0;
    }
}

void BLAKE3_Read4(
    blake3_t *restrict x,
    void *restrict out,
    size_t len, int flags)
{
    static_assert(sizeof(uint32_t) == 4, "Data type assumption failed!");
    uint32_t h[16] = {0};
    uint8_t *ptr = out;
    uint8_t *blk = NULL;

    // I could use ``int'', but I want to silence the
    // unnecessary differing-sign warning.
    unsigned i;
    uint32_t b, s;

    blake3_node_t *node;

    // should also work when it's ``x->nodes + 0''.
    node = x->nodes + x->nind[0];

    b = node->remain & 63;
    s = node->remain ^ b;
    if( b == 0 && s > 0 )
    {
        b = 64;
        s -= 64;
    }

    if( flags & HASHING_READ4_REWIND )
        x->t = 0;

    while( len )
    {
        if( x->t % 64 == 0 || !blk )
        {
            for(i=0; i<8; i++) h[i] = x->k.u32[i];

            blake3_compress(
                h, node->buf.u32 + (s / 4),
                x->t / 64, b, node->d);
            
            for(i=0; i<16; i++) h[i] = htole32(h[i]);
            blk = (void *)h;
            blk += x->t % 64;
        }

        *ptr++ = *blk++;
        x->t++;
        len--;
    }
}

IntPtr iBLAKE3(int q){ return xBLAKE3(q); }
