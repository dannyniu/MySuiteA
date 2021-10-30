/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsassa-pss.h"
#include "../2-rsa/rsa-codec-der.h"
#include "../2-hash/sha.h"

#include "../test-utils.c.h"
#include "../2-xof/gimli-xof.h"
static gimli_xof_t gx;

#define NBITS 768
#define MSGMAX 96

void *my_alloc(const char *s, size_t len)
{
    printf("my_alloc: %s: %zd bytes\n", s, len);
    return malloc(len);
}

int main(int argc, char *argv[])
{
    IntPtr lret;
    size_t size;

#include "test-self-fed-test.c.h"
    
    printf("tests start\n");

    int failures = 0;
    int testcount = 80 / 5;

    uint32_t dword; // data word that receives output from PRNG.
    size_t msglen = MSGMAX;
    void *msg = malloc(msglen);
    // void *sig = copy;

    //dumphex(dex, 1328);
    //dumphex(enx, 780);

    for(int i=1; i<=testcount; i++)
    {
        printf("\t""test %d of %d\r", i, testcount);
        fflush(NULL);

        Gimli_XOF_Read(&gx, &dword, sizeof(dword));
        msglen = dword % MSGMAX;

        Gimli_XOF_Read(&gx, msg, msglen);

        RSASSA_PSS_Sign(dex, msg, msglen, (GenFunc_t)Gimli_XOF_Read, &gx);
        RSASSA_PSS_Encode_Signature(dex, NULL, &size);

        if( !copy ) copy = malloc(size);

        if( !copy )
        {
            perror("malloc 3");
            exit(EXIT_FAILURE);
        }

        RSASSA_PSS_Encode_Signature(dex, copy, &size);
        RSASSA_PSS_Decode_Signature(&enx.header, copy, size);

        lret = (IntPtr)RSASSA_PSS_Verify(&enx.header, msg, msglen);
        if( !lret )
        {
            printf("%d: Signature Failure\n", i);
            failures ++;
            break;
        }
    }

    printf("\n%d of %d tests failed\n", failures, testcount);
    free(copy);
    return 0;
}
