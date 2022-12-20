/* DannyNiu/NJF, 2022-08-29. Public Domain. */

#include "blake3.h"
#include "../1-oslib/TCrew.h"

void BLAKE3_Update(
    blake3_t *restrict x,
    void const *restrict data,
    size_t len);

void BLAKE3_Final(
    blake3_t *restrict x,
    void *restrict out,
    size_t t);

#define xBLAKE3_ForTest(q) (\
        q==outBytes ? 131 :\
        q==UpdateFunc ? (IntPtr)BLAKE3_Update :\
        q==FinalFunc ? (IntPtr)BLAKE3_Final :\
        xBLAKE3(q) )

#undef h
#define h xBLAKE3_ForTest
#include "hash-test.c.h"

void BLAKE3_Update(
    blake3_t *restrict x,
    void const *restrict data,
    size_t len)
{
    BLAKE3_Update4(x, data, len, &tcrew_shared.funcstab);
}

void BLAKE3_Final(blake3_t *restrict x, void *restrict out, size_t t)
{
    size_t l;
    uint8_t *ptr = out;

    BLAKE3_Final2(x, &tcrew_shared.funcstab);

    while( t > 0 )
    {
        l = myrand()+1;
        if( l > t ) l = t;

        BLAKE3_Read4(x, ptr, l, 0);
        t -= l;
        ptr += l;
    }
}

int main(int argc, char *argv[])
{
    if( argc < 2 ) return EXIT_FAILURE;

    test1case(xBLAKE3_ForTest);

    return EXIT_SUCCESS;
}
