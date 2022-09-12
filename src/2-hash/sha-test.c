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

    test1case(iSHA1);
    test1case(iSHA224);
    test1case(iSHA256);
    test1case(iSHA384);
    test1case(iSHA512);
    test1case(iSHA512t224);
    test1case(iSHA512t256);

    return EXIT_SUCCESS;
}
