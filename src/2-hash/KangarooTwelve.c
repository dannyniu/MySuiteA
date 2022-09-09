/* DannyNiu/NJF, 2022-09-06. Public Domain. */

#include "KangarooTwelve.h"

#define KP12_BlkBytes 200

static void KeccakP1600nr12_Permute(void const *in, void *out)
{
    KeccakP1600_Permute(in, out, 12);
}

#define xKeccakP1600nr12(q) (                                   \
        q==blockBytes ? KP12_BlkBytes :                         \
        q==PermuteFunc ? (IntPtr)KeccakP1600nr12_Permute :      \
        0)

static void KeccakP1600nr14_Permute(void const *in, void *out)
{
    KeccakP1600_Permute(in, out, 14);
}

#define xKeccakP1600nr14(q) (                                   \
        q==blockBytes ? KP12_BlkBytes :                         \
        q==PermuteFunc ? (IntPtr)KeccakP1600nr14_Permute :      \
        0)

typedef struct {
    sponge_t sponge;
    union {
        uint8_t u8[200];
        uint64_t u64[25];
    } state;
} sponge_proc_t;

#define KP12or14(q) ( rate == 168 ? xKeccakP1600nr12(q) : xKeccakP1600nr14(q) )

static void hash1inode(k12_inner_node_t *node, unsigned rate)
{
    sponge_proc_t proc = {
        .sponge = SPONGE_INIT(rate, 0x0B, 0x80, KP12or14),
        .state.u8 = {0},
    };

    // would've been ``size_t'', but not for any practical usefulness.
    // ``uint32_t'' is that of ``k12_inner_node_t::filled''.
    uint32_t cvsize = KP12_BlkBytes - rate;

    Sponge_Update(&proc.sponge, node->buf, node->filled);
    Sponge_Final(&proc.sponge);
    Sponge_Read(&proc.sponge, node->buf, cvsize);

    node->filled = cvsize;
    node->hashed = true;
}

static void init1inode(k12_inner_node_t *node, unsigned id)
{
    size_t t;
    node->me = id;
    node->hashed = false;
    node->filled = 0;
    for(t=0; t<sizeof(node->buf); t++) node->buf[t] = 0;
}

static void K12_Init(K12_Ctx_t *x, unsigned rate)
{
    unsigned t;

    for(t=0; t<K12_NODES_COUNT; t++)
        init1inode(x->inodes+t, t);

    // the lo-pad will be altered by internal routine
    // when the size of the input message exceeds 8192 bytes.
    x->finalnode.sponge = SPONGE_INIT(rate, 0x07, 0x80, KP12or14);

    for(t=0; t<sizeof(x->finalnode.buf.u8); t++)
        x->finalnode.buf.u8[t] = 0;

    x->total = 0;
    x->clen = 0;
    x->inodes_filled = 0;
    x->finalized = false;
}

void KangarooTwelve_Init(KangarooTwelve_t *x)
{
    K12_Init(x, KP12_BlkBytes-32);
}

void MarsupilamiFourteen_Init(KangarooTwelve_t *x)
{
    K12_Init(x, KP12_BlkBytes-64);
}

static void job_leaf2cv(k12_inner_node_t *node)
{
    K12_Ctx_t *x;
    uint8_t *ptr = (void *)node;
    ptr -= offsetof(K12_Ctx_t, inodes[node->me]);
    x = (void *)ptr;

    hash1inode(node, x->finalnode.sponge.rate);
}

static void cv2final(K12_Ctx_t *x)
{
    unsigned t;
    for(t=0; t<x->inodes_filled; t++)
    {
        k12_inner_node_t *node = x->inodes + t;

        Sponge_Update(&x->finalnode.sponge, node->buf, node->filled);
        init1inode(node, node->me);
    }
    x->inodes_filled = 0;
}

void K12_Update4(
    K12_Ctx_t *restrict x,
    void const *restrict dat,
    size_t len,
    TCrew_Abstract_t *restrict tc)
{
    uint8_t const *ptr = dat;

    while( len && x->total < 8192 )
    {
        size_t ulen = len;
        if( ulen + x->total > 8192 ) ulen = 8192 - x->total;

        Sponge_Update(&x->finalnode.sponge, ptr, ulen);
        ptr += ulen;
        len -= ulen;
        x->total += ulen;
    }

    if( len && x->total == 8192 )
    {
        static const uint8_t octabyte[8] = { 003, 0, 0, 0,  0, 0, 0, 0 };
        x->finalnode.sponge.lopad = 0x06;
        Sponge_Update(&x->finalnode.sponge, octabyte, 8);
    }

    while( len )
    {
        k12_inner_node_t *node;

        node = x->inodes + x->inodes_filled;

        node->buf[node->filled++] = *ptr++;
        len--;
        x->total++;

        assert( node->filled <= 8192 );
        if( node->filled == 8192 )
            x->inodes_filled++;

        assert( x->inodes_filled <= K12_NODES_COUNT );
        if( x->inodes_filled == K12_NODES_COUNT )
        {
            unsigned t;

            for(t=0; t<x->inodes_filled; t++)
            {
                k12_inner_node_t *node = x->inodes + t;
                tc->enqueue(tc, (TCrew_Assignment_t)job_leaf2cv, node);
            }

            tc->wait(tc, (TCrew_Assignment_t)cv2final, x);
        }
    }
}

void K12_Final2(K12_Ctx_t *restrict x, TCrew_Abstract_t *restrict tc)
{
    uint64_t n;
    size_t t;
    k12_inner_node_t *node;

    uint8_t l;
    uint8_t b, c;

    // finalization guard. //

    if( x->finalized ) return;

    // record the length of the customization string. //

    n = x->clen;
    l = 0;
    while( l < 8 && n >= (1 << (l << 3)) ) l++;

    for(b=l; b-->0; )
    {
        c = n >> (b << 3);
        K12_Update4(x, &c, 1, tc);
    }
    K12_Update4(x, &l, 1, tc);

    // short message, no overhead. //

    if( x->total <= 8192 ) goto finish;

    // long message, overhead. //

    node = x->inodes + x->inodes_filled;
    if( node->filled > 0 ) x->inodes_filled++;

    for(t=0; t<x->inodes_filled; t++)
    {
        k12_inner_node_t *node = x->inodes + t;
        tc->enqueue(tc, (TCrew_Assignment_t)job_leaf2cv, node);
    }

    tc->wait(tc, (TCrew_Assignment_t)cv2final, x);

    n = (x->total + 8191) / 8192;
    n = n - 1;
    l = 0;
    while( l < 8 && n >= (1 << (l << 3)) ) l++;

    for(b=l; b-->0; )
    {
        c = n >> (b << 3);
        Sponge_Update(&x->finalnode.sponge, &c, 1);
    }
    Sponge_Update(&x->finalnode.sponge, &l, 1);

    c = 0xff;
    Sponge_Update(&x->finalnode.sponge, &c, 1);
    Sponge_Update(&x->finalnode.sponge, &c, 1);
    goto finish;

    // finishing. common to both short and long messages. //

finish:
    Sponge_Final(&x->finalnode.sponge);
    for(t=0; t<KP12_BlkBytes; t++)
    {
        x->inodes[0].buf[t] = x->finalnode.buf.u8[t];
    }

    x->finalized = true;
    return;
}

void K12_Read4(
    K12_Ctx_t *restrict x,
    void *restrict out,
    size_t len, int flags)
{
    size_t t;

    if( flags & HASHING_READ4_REWIND )
    {
        for(t=0; t<KP12_BlkBytes; t++)
        {
            x->finalnode.buf.u8[t] = x->inodes[0].buf[t];
        }

        x->finalnode.sponge.filled = 0;
    }

    Sponge_Read(&x->finalnode.sponge, out, len);
}

void *K12_Xctrl(
    K12_Ctx_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    (void)veclen;
    (void)flags;

    switch( cmd )
    {
    case K12_cmd_Feed_CStr:
        x->clen += bufvec[0].len;
        K12_Update4(x, bufvec[0].dat, bufvec[0].len, bufvec[1].buf);
        return x;
        break;

    default:
        return NULL;
    }
}

IntPtr iKangarooTwelve(int q){ return xKangarooTwelve(q); }
IntPtr iMarsupilamiFourteen(int q){ return xMarsupilamiFourteen(q); }
