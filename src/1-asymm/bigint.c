/* DannyNiu/NJF, 2018-03-01. Public Domain. */

#include "bigint.h"

static inline int bn_nz(long n, bn_t *x)
{
    for(long i=0; i<n; i++) if( x->w[i] ) return 1;
    return 0;
}

void bn_egcd(long n, egcd_t *restrict egcd, bn_t *out, const bn_t *a, const bn_t *p)
{
    unsigned iteration = 0;

    // Remainder: There was a skip error.
    // Check and recheck the offsets are in sequence. 
#define i  egcd->ijr[(iteration+0)%4]
#define j  egcd->ijr[(iteration+1)%4]
#define r  egcd->ijr[(iteration+2)%4]
#define q  egcd->ijr[(iteration+3)%4]
#define y2 egcd->yyy[(iteration+0)%4]
#define y1 egcd->yyy[(iteration+1)%4]
#define y  egcd->yyy[(iteration+2)%4]

    bn_add(n, i, p, NULL, 0);
    bn_add(n, j, a, NULL, 0);
    bn_add(n, y2, NULL, NULL, 0);
    bn_add(n, y1, NULL, NULL, 1);

    for(; bn_nz(n, j); iteration++) {
        bn_div(n, q, r, i, j);
        bn_mul(n, y, y1, q);
        bn_sub(n, y, y2, y, 0);
    }

    i->w[0] -= 1; // i should equal 1 at this point.
    if( bn_nz(n, i) ) { // compare after subtracting.
        bn_add(n, out, NULL, NULL, 0); // a and p are not coprime.
    }
    else {
        if( (int32_t)y2->w[n-1] < 0 )
            bn_add(n, out, y2, p, 0);
        else bn_add(n, out, y2, NULL, 0);
    }
    
#undef i
#undef j
#undef r
#undef q
#undef y2
#undef y1
#undef y
}

void bn_mont_set_N(long n, mont_t *restrict mont, egcd_t *restrict egcd, const bn_t *N)
{
    long i;
    
    mont->logR_base32 = 0;

    for(i=0; i<n; i++) {
        if( (mont->N->w[i] = N->w[i]) )
            mont->logR_base32 = i+1;

        mont->R_inv->w[i] = 0;
    }

    if( mont->logR_base32 * 2 >= n ) return; // Maybe assert?
    
    mont->R_inv->w[mont->logR_base32] = 1;
    bn_egcd(n, egcd, mont->R_inv, mont->R_inv, mont->N);

    for(i=0; i<n; i++) {
        mont->m->w[i] =
            i < mont->logR_base32 ? 0 :
            mont->R_inv->w[i - mont->logR_base32];
    }

    bn_div(n, mont->N_apos, mont->m, mont->m, mont->N);
    return;
}

void bn_mont_convert(long n, mont_t *restrict mont, bn_t *out, const bn_t *a)
{
    long i;

    for(i=n; i--; ) { // this direction is necessary to ensure restrict-free pointers. 
        out->w[i] = 
            i < mont->logR_base32 ? 0 :
            a->w[i - mont->logR_base32];
    }
    
    bn_div(n, NULL, out, out, mont->N);
}

static int bn_ge(long n, const bn_t *a, const bn_t *b)
{
    for(long i=n; i--; ) {
        uint32_t u = a->w[i];
        uint32_t v = b->w[i];
        if( u < v ) { return 0; } else if( u > v ) { break; }
    }
    return 1;
}

void bn_mont_REDC(long n, mont_t *restrict mont, bn_t *out, const bn_t *T)
{
    long i;

    for(i=0; i<mont->logR_base32; i++) mont->t->w[i] = T->w[i];
    for(i=mont->logR_base32; i<n; i++) mont->t->w[i] = 0;
    
    bn_mul(n, mont->m, mont->t, mont->N_apos);

    for(i=mont->logR_base32; i<n; i++) mont->m->w[i] = 0;
    
    bn_mul(n, mont->t, mont->m, mont->N);
    bn_add(n, mont->t, mont->t, T, 0);

    for(i=0; i+mont->logR_base32<n; i++)
        mont->t->w[i] = mont->t->w[i+mont->logR_base32];

    for(i=n-mont->logR_base32; i<n; i++)
        mont->t->w[i] = 0;

    bn_sub(n, out, mont->t,
           (bn_ge(n, mont->t, mont->N) ? mont->N : NULL), 0);
}

void bn_mont_modexp(long n, mont_t *restrict mont,
                    bn_t *out,
                    const bn_t *restrict b,
                    const bn_t *restrict e,
                    bn_t *restrict tmp)
{
    long i;

    out->w[0] = 1; for(i=1; i<n; i++) { out->w[i] = 0; }
    bn_mont_convert(n, mont, out, out);
    
    for(i=n*32; i--; ) {
        if( (e->w[i/32] >> i%32) & 1 ) {
            bn_mul(n, tmp, out, b);
            bn_mont_REDC(n, mont, out, tmp);
        }
        if( i ) {
            bn_mul(n, tmp, out, out);
            bn_mont_REDC(n, mont, out, tmp);
        }
    }
}
