/* DannyNiu/NJF, 2021-07-19. Public Domain. */

#undef bc
#define bc xARIA128
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc xARIA192
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc xARIA256
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc iARIA128
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc iARIA192
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc iARIA256
#include "../1-symm/blockcipher-test.c.h"

int main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;

    if( argc < 2 ) return EXIT_FAILURE;
    
    if( !strcmp(argv[1], "128") )
    {
        ret =
            blockcipher_test_xARIA128() == EXIT_SUCCESS &&
            blockcipher_test_iARIA128() == EXIT_SUCCESS ?
            EXIT_SUCCESS : EXIT_FAILURE;
    }

    if( !strcmp(argv[1], "192") )
    {
        ret =
            blockcipher_test_xARIA192() == EXIT_SUCCESS &&
            blockcipher_test_iARIA192() == EXIT_SUCCESS ?
            EXIT_SUCCESS : EXIT_FAILURE;
    }

    if( !strcmp(argv[1], "256") )
    {
        ret =
            blockcipher_test_xARIA256() == EXIT_SUCCESS &&
            blockcipher_test_iARIA256() == EXIT_SUCCESS ?
            EXIT_SUCCESS : EXIT_FAILURE;
    }
    
    return ret;
}
