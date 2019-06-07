/* DannyNiu/NJF, 2019-05-26. Public Domain. */

#include "largeint.h"
#include "../0-datum/endian.h"

static inline uint32_t w32toh(const uint32_t p, unsigned msb)
{
    return msb ? be32toh(p) : le32toh(p);
}

static inline uint32_t htow32(const uint32_t p, unsigned msb)
{
    return msb ? htobe32(p) : htole32(p);
}

uint64_t intdesc_getword32(const struct intdesc intd, unsigned i)
{
    if( i >= intd.len ) return 0;
    if( intd.msw )
        return w32toh(intd.c[intd.len - i - 1], intd.msb);
    else return w32toh(intd.c[i], intd.msb);
}

void intdesc_setword32(const struct intdesc intd, unsigned i, uint32_t x)
{
    if( i >= intd.len ) return;
    if( intd.msw )
        intd.p[intd.len - i - 1] = htow32(x, intd.msb);
    else intd.p[i] = htow32(x, intd.msb);
}

uint64_t intview_getword32(const struct intview intv, unsigned i)
{
    if( i >= intv.len ) return 0;
    return intdesc_getword32(intv.intd, i+intv.base);
}

void intview_setword32(const struct intview intv, unsigned i, uint32_t x)
{
    if( i >= intv.len ) return;
    intdesc_setword32(intv.intd, i+intv.base, x);
}

#define getword32(s, i)                                 \
    _Generic(s,                                         \
             struct intdesc: intdesc_getword32,         \
             struct intview: intview_getword32 )(s, i)

#define setword32(s, i, x)                                      \
    _Generic(s,                                                 \
             struct intdesc: intdesc_setword32,                 \
             struct intview: intview_setword32 )(s, i, x)

void li_add(
    const struct intdesc out,
    const struct intdesc a,
    const struct intdesc b)
{
    uint64_t x = 0;
    unsigned i;
    for(i=0; i<out.len || i<a.len || i<b.len; i++)
    {
        x += getword32(a, i) + getword32(b, i);
        setword32(out, i, x);
        x >>= 32;
    }
}

void li_sub(
    const struct intdesc out,
    const struct intdesc a,
    const struct intdesc b)
{
    uint64_t x = 0;
    unsigned i;
    for(i=0; i<out.len || i<a.len || i<b.len; i++)
    {
        x += getword32(a, i) - getword32(b, i);
        setword32(out, i, x);
        x = (int64_t)(int32_t)(x>>32); // sign-extending. 
    }
}
    
void li_mul(
    const struct intdesc out,
    const struct intdesc a,
    const struct intdesc b)
{
    uint64_t x;
    unsigned i, j;

    for(i=0; i<out.len; i++) setword32(out, i, 0);
    
    for(i=0; i<a.len; i++)
    {
        x = 0;
        for(j=0; j<b.len; j++)
        {
            if( i+j >= out.len ) break;
            x >>= 32;
            x += getword32(a, i) * getword32(b, j);
            x += getword32(out, i+j);
            setword32(out, i+j, x);
        }
    }
}

static inline uint32_t getword32s(const struct intview intv, unsigned t)
{
    // get word shifted.

    // exotic sign extension on unsigned integer. 
    const static unsigned m = UINT_MAX ^ UINT_MAX >> 5;
    const static unsigned b = UINT_MAX ^ INT_MAX;
    unsigned i = t >> 5 | ( t&b ? m : 0 );
        
    if( t & 31 )
    {
        unsigned s = t & 31;
        unsigned r = 32 - s;
        return
            getword32(intv, i+0) >> s |
            getword32(intv, i+1) << r ;
    }
    else
    {
        return getword32(intv, i);
    }
}

static int shifted_ge(const struct intview a, const struct intview b, unsigned t)
{
    // evaluates the expression: a >= (b << t)
    
    unsigned m = a.len, n = b.len + (t+31)/32;

    for(unsigned i = m>n?m:n; i--; )
    {
        uint32_t
            u = getword32(a, i),
            v = getword32s(b, i*32-t);
        
        if( u < v ) return 0; else if( u > v ) break;
    }

    return 1;
}

static void shifted_sub(
    const struct intview out,
    const struct intview a,
    const struct intview b,
    unsigned t)
{
    uint64_t x = 0;
    unsigned i;
    for(i=0; i<out.len || i<a.len || i<b.len; i++)
    {
        x += getword32(a, i) - getword32s(b, i*32-t);
        setword32(out, i, x);
        x = (int64_t)(int32_t)(x>>32); // sign-extending. 
    }
}

void li_div(
    const struct intdesc quo,
    const struct intdesc rem,
    const struct intdesc a,
    const struct intdesc b)
{
    unsigned i, n;

    struct intdesc wv; // working variable.
    struct intview q, r, d;
    uint32_t h, g;

    if( quo.p ) for(i=0; i<quo.len; i++) setword32(quo, i, 0);
    if( rem.p ) for(i=0; i<rem.len; i++) setword32(rem, i, 0);

    // design decision:
    // work on variables truncated to the shortest of all provided intdesc. 
    n = 0;
    if( !n || quo.len < n ) n = quo.len;
    if( !n || rem.len < n ) n = rem.len;
    if( !n || a.len < n ) n = a.len;
    if( !n || b.len < n ) n = b.len;
    if( !n ) return;

    if( rem.p ) wv = rem; else wv = quo;
    if( !wv.p ) return;

    q.intd = r.intd = wv;
    q.base = n, q.len = 0;
    r.base = 0, r.len = n;

    d.intd = b;
    d.base = 0, d.len = n;
    
    for(i=0; i<n; i++)
        setword32(r, i, getword32(a, i));
    
    h = g = 0;
    
    for(i=n*32; i--; )
    {
        if( shifted_ge(r, d, i) )
        {
            shifted_sub(r, r, d, i);
            h |= UINT32_C(1) << i%32;
        }
        
        if( i & 31 ) continue;

        if( g == 0 )
        {
            g = h;
            h = 0;
        }
        else if( getword32(r, r.len-1) == 0 )
        {
            r.len--; q.base--; q.len++;
            setword32(q, 0, h);
            h = 0;
        }
    }

    if( rem.p )
    {
        for(i=0; i<r.len; i++) // must not erase quotient yet. 
            setword32(rem, i, getword32(r, i));
    }

    if( quo.p )
    {
        // must not modify r.len here. because --

        for(i=0; i<n && i<q.len; i++)
            setword32(quo, i, getword32(q, i));

        setword32(quo, i++, g);

        for(; i<n; i++)
            setword32(quo, i, 0);
    }

    if( rem.p )
    {
        for(i=r.len; i<n; i++) // -- because it's needed here.
            setword32(rem, i, 0);
    }
}
