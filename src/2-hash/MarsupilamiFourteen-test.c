/* DannyNiu/NJF, 2022-09-09. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "KangarooTwelve.h"
#include "../1-oslib/TCrew-Stub.h"

#include "../test-utils.c.h"

MarsupilamiFourteen_t sh;
#define BUF_LEN 256

int main(int argc, char *argv[])
{
    bufvec_t bv[2];
    char buf[BUF_LEN];
    unsigned long msglen = atol(argv[1]);
    size_t rlen, tlen;

    if( argc != 2 ) return 1;

    tlen = 0;
    MarsupilamiFourteen_Init(&sh);

    while( tlen < msglen )
    {
        rlen = BUF_LEN;
        if( rlen + tlen > msglen ) rlen = msglen - tlen;
        fread(buf, 1, rlen, stdin);
        K12_Update4(&sh, buf, rlen, &tcrew_stub.funcstab);
        tlen += rlen;
    }

    while( !feof(stdin) )
    {
        bv[0].dat = buf;
        bv[0].len = fread(bv[0].buf, 1, BUF_LEN, stdin);
        bv[1].buf = &tcrew_stub;
        K12_Xctrl(&sh, K12_cmd_Feed_CStr, bv, 2, 0);
    }

    K12_Final2(&sh, &tcrew_stub.funcstab);
    K12_Read4(&sh, buf, BUF_LEN, HASHING_READ4_REWIND);
    fwrite(buf, 1, BUF_LEN, stdout);

    return 0;
}
