/* DannyNiu/NJF, 2018-02-05. Public Domain. */

#include "../0-datum/endian.h"
#include "../1-symm-national/gbt-32905.h"
#include "sm3.h"

void SM3_Update(sm3_t *restrict x, void const *restrict data, size_t len)
{
    const uint8_t *ptr = data;
    
    // Msg must not be full when this loop enters.
    while(len)
    {
        x->Msg8[x->filled++] = *ptr++;
        len--;

        if( x->filled == sizeof(x->Msg8) ) {
            compressfunc_sm3(x->H, x->Msg32);
            x->filled = 0;
        }
    }

    x->len += (uint64_t)(ptr - (const uint8_t *)data) * 8;
}

static void sm3_final(sm3_t *restrict x)
{
    int i;
    if( x->finalized ) return;
    
    if( x->filled / sizeof(uint32_t) >= 14 )
    {
        x->Msg8[x->filled++] = 0x80;
        while( x->filled < sizeof(x->Msg8) )
            x->Msg8[x->filled++] = 0;
        compressfunc_sm3(x->H, x->Msg32);
        x->filled = 0;

        while( x->filled < sizeof(x->Msg8) )
            x->Msg8[x->filled++] = 0;
        x->filled = 0;
    }
    else
    {
        x->Msg8[x->filled++] = 0x80;
        while( x->filled < sizeof(x->Msg8) )
            x->Msg8[x->filled++] = 0;
        x->filled = 0;
    }

    x->Msg32[14] = htobe32((uint32_t)(x->len >> 32));
    x->Msg32[15] = htobe32((uint32_t)(x->len));
    compressfunc_sm3(x->H, x->Msg32);
    for(i=0; i<8; i++)
        x->Msg32[i] = htobe32(x->H[i]);
    x->finalized = 1;
}

void SM3_Init(sm3_t *restrict x)
{
    x->finalized = 0;
    x->len = 0;
    x->H[0] = 0x7380166f;
    x->H[1] = 0x4914b2b9;
    x->H[2] = 0x172442d7;
    x->H[3] = 0xda8a0600;
    x->H[4] = 0xa96f30bc;
    x->H[5] = 0x163138aa;
    x->H[6] = 0xe38dee4d;
    x->H[7] = 0xb0fb0e4e;
    x->filled = 0;
}

void SM3_Final(sm3_t *restrict x, void *restrict out, size_t t)
{
    uint8_t *ptr = out;
    size_t i;

    sm3_final(x);
    
    if( out )
    {
        for(i=0; i<t; i++)
            ptr[i] = i<32 ? x->Msg8[i] : 0;
    }
}

IntPtr iSM3(int q){ return cSM3(q); }
