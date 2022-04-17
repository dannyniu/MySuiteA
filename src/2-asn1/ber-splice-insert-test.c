/* DannyNiu/NJF, 2021-02-28. Public Domain. */

#include "der-codec.h"
#include "../test-utils.c.h"

#define BUFLEN 512

int main()
{
    uint8_t buf[BUFLEN];
    uint8_t verify[BUFLEN];
    size_t l1, o, l2;
    int i, j;
    int ret = EXIT_SUCCESS;

    mysrand((unsigned long)time(NULL));

    for(j=0; j<100000; j++)
    {
        for(i=0; i<BUFLEN; i++) verify[i] = buf[i] = myrand();

        l2 = myrand() % 17;
        l1 = myrand() % 17;
        o = myrand() % 17 + l1;

        ber_util_splice_insert(verify, l1, o, l2);

        if( memcmp(verify, buf + o, l2) )
        {
            ret = EXIT_FAILURE;
            printf("Src error: l1=%zd, o=%zd, l2=%zd. \n", l1, o, l2);
        }

        if( memcmp(verify + l2, buf, l1) )
        {
            ret = EXIT_FAILURE;
            printf("Dst error: l1=%zd, o=%zd, l2=%zd. \n", l1, o, l2);
        }
    }

    if( ret == EXIT_SUCCESS )
        printf("All Tests Passed.\n");

    return ret;
}
