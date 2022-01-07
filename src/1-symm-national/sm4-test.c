/* DannyNiu/NJF, 2021-06-23. Public Domain. */

#undef bc
#define bc xSM4
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc iSM4
#include "../1-symm/blockcipher-test.c.h"

int main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;

    if( argc < 2 ) return EXIT_FAILURE;
    
    if( !strcmp(argv[1], "128") )
    {
        ret =
            blockcipher_test_xSM4() == EXIT_SUCCESS &&
            blockcipher_test_iSM4() == EXIT_SUCCESS ?
            EXIT_SUCCESS : EXIT_FAILURE;
    }
    
    return ret;
}
