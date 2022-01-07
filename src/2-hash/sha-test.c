/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#undef h
#define h xSHA1
#include "hash-test.c.h"

#undef h
#define h xSHA224
#include "hash-test.c.h"

#undef h
#define h xSHA256
#include "hash-test.c.h"

#undef h
#define h xSHA384
#include "hash-test.c.h"

#undef h
#define h xSHA512
#include "hash-test.c.h"

#undef h
#define h xSHA512t224
#include "hash-test.c.h"

#undef h
#define h xSHA512t256
#include "hash-test.c.h"

#undef h
#define h xSHA3_224
#include "hash-test.c.h"

#undef h
#define h xSHA3_256
#include "hash-test.c.h"

#undef h
#define h xSHA3_384
#include "hash-test.c.h"

#undef h
#define h xSHA3_512
#include "hash-test.c.h"

#undef h
#define h iSHA1
#include "hash-test.c.h"

#undef h
#define h iSHA224
#include "hash-test.c.h"

#undef h
#define h iSHA256
#include "hash-test.c.h"

#undef h
#define h iSHA384
#include "hash-test.c.h"

#undef h
#define h iSHA512
#include "hash-test.c.h"

#undef h
#define h iSHA512t224
#include "hash-test.c.h"

#undef h
#define h iSHA512t256
#include "hash-test.c.h"

#undef h
#define h iSHA3_224
#include "hash-test.c.h"

#undef h
#define h iSHA3_256
#include "hash-test.c.h"

#undef h
#define h iSHA3_384
#include "hash-test.c.h"

#undef h
#define h iSHA3_512
#include "hash-test.c.h"

void SHA3_128000_Final(void *restrict x, void *restrict out, size_t t)
{ SHAKE_Final(x); SHAKE_Read(x, out, t); }

void SHA3_256000_Final(void *restrict x, void *restrict out, size_t t)
{ SHAKE_Final(x); SHAKE_Read(x, out, t); }

IntPtr iSHA3_128000(int q){
    return (
        q==outBytes ? 256 :
        q==blockBytes ? 168 :
        q==contextBytes ? sizeof(struct shake_context) :
        q==InitFunc   ? (IntPtr)SHAKE128_Init :
        q==UpdateFunc ? (IntPtr)SHAKE_Write :
        q==FinalFunc  ? (IntPtr)SHA3_128000_Final :
        0);
}

IntPtr iSHA3_256000(int q){
    return (
        q==outBytes ? 256 :
        q==blockBytes ? 136 :
        q==contextBytes ? sizeof(struct shake_context) :
        q==InitFunc   ? (IntPtr)SHAKE256_Init :
        q==UpdateFunc ? (IntPtr)SHAKE_Write :
        q==FinalFunc  ? (IntPtr)SHA3_256000_Final :
        0);
}

IntPtr (*xSHA3_128000)(int q) = iSHA3_128000;
IntPtr (*xSHA3_256000)(int q) = iSHA3_256000;

#undef h
#define h xSHA3_128000
#include "hash-test.c.h"

#undef h
#define h xSHA3_256000
#include "hash-test.c.h"

#undef h
#define h iSHA3_128000
#include "hash-test.c.h"

#undef h
#define h iSHA3_256000
#include "hash-test.c.h"

int main(int argc, char *argv[])
{
    if( argc < 2 ) return EXIT_FAILURE;

    test1case(xSHA1);
    test1case(xSHA224);
    test1case(xSHA256);
    test1case(xSHA384);
    test1case(xSHA512);
    test1case(xSHA512t224);
    test1case(xSHA512t256);
    test1case(xSHA3_224);
    test1case(xSHA3_256);
    test1case(xSHA3_384);
    test1case(xSHA3_512);
    test1case(xSHA3_128000);
    test1case(xSHA3_256000);

    test1case(iSHA1);
    test1case(iSHA224);
    test1case(iSHA256);
    test1case(iSHA384);
    test1case(iSHA512);
    test1case(iSHA512t224);
    test1case(iSHA512t256);
    test1case(iSHA3_224);
    test1case(iSHA3_256);
    test1case(iSHA3_384);
    test1case(iSHA3_512);
    test1case(iSHA3_128000);
    test1case(iSHA3_256000);
    
    return EXIT_SUCCESS;
}
