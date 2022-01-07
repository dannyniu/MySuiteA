/* DannyNiu/NJF, 2021-07-20. Public Domain. */

#undef h
#define h xSM3
#include "hash-test.c.h"

#undef h
#define h iSM3
#include "hash-test.c.h"

int main(int argc, char *argv[])
{
    if( argc < 2 ) return EXIT_FAILURE;

    test1case(xSM3);
    test1case(iSM3);
    
    return EXIT_SUCCESS;
}
