/* DannyNiu/NJF, 2018-12-23. Public Domain. */

#undef h
#define h xBLAKE2b160
#include "hash-test.c.h"

#undef h
#define h xBLAKE2b256
#include "hash-test.c.h"

#undef h
#define h xBLAKE2b384
#include "hash-test.c.h"

#undef h
#define h xBLAKE2b512
#include "hash-test.c.h"

#undef h
#define h xBLAKE2s128
#include "hash-test.c.h"

#undef h
#define h xBLAKE2s160
#include "hash-test.c.h"

#undef h
#define h xBLAKE2s224
#include "hash-test.c.h"

#undef h
#define h xBLAKE2s256
#include "hash-test.c.h"

#undef h
#define h iBLAKE2b160
#include "hash-test.c.h"

#undef h
#define h iBLAKE2b256
#include "hash-test.c.h"

#undef h
#define h iBLAKE2b384
#include "hash-test.c.h"

#undef h
#define h iBLAKE2b512
#include "hash-test.c.h"

#undef h
#define h iBLAKE2s128
#include "hash-test.c.h"

#undef h
#define h iBLAKE2s160
#include "hash-test.c.h"

#undef h
#define h iBLAKE2s224
#include "hash-test.c.h"

#undef h
#define h iBLAKE2s256
#include "hash-test.c.h"

int main(int argc, char *argv[])
{
    if( argc < 2 ) return EXIT_FAILURE;

    test1case(xBLAKE2b160);
    test1case(xBLAKE2b256);
    test1case(xBLAKE2b384);
    test1case(xBLAKE2b512);
    test1case(xBLAKE2s128);
    test1case(xBLAKE2s160);
    test1case(xBLAKE2s224);
    test1case(xBLAKE2s256);

    test1case(iBLAKE2b160);
    test1case(iBLAKE2b256);
    test1case(iBLAKE2b384);
    test1case(iBLAKE2b512);
    test1case(iBLAKE2s128);
    test1case(iBLAKE2s160);
    test1case(iBLAKE2s224);
    test1case(iBLAKE2s256);

    return EXIT_SUCCESS;
}
