/* DannyNiu/NJF, 2022-09-08. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "KangarooTwelve.h"
#include "../1-oslib/TCrew.h"

#include "../test-utils.c.h"

#define HASH_LEN 64

static const struct {
    long mlen, clen, skip, outlen;
    const char *ref;
} testvecs[] = {
    {
        0, 0, 0, 32,
        "1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca 1b 37 51"
        "3c 08 03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5",
    },

    {
        0, 0, 0, 64,
        "1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca 1b 37 51"
        "3c 08 03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5"
        "42 69 c0 56 b8 c8 2e 48 27 60 38 b6 d2 92 96 6c"
        "c0 7a 3d 46 45 27 2e 31 ff 38 50 81 39 eb 0a 71",
    },

    {
        0, 0, 10000, 32,
        "e8 dc 56 36 42 f7 22 8c 84 68 4c 89 84 05 d3 a8"
        "34 79 91 58 c0 79 b1 28 80 27 7a 1d 28 e2 ff 6d",
    },

    {
        1, 0, 0, 32,
        "2b da 92 45 0e 8b 14 7f 8a 7c b6 29 e7 84 a0 58"
        "ef ca 7c f7 d8 21 8e 02 d3 45 df aa 65 24 4a 1f",
    },

    {
        17, 0, 0, 32,
        "6b f7 5f a2 23 91 98 db 47 72 e3 64 78 f8 e1 9b"
        "0f 37 12 05 f6 a9 a9 3a 27 3f 51 df 37 12 28 88",
    },

    {
        17*17, 0, 0, 32,
        "0c 31 5e bc de db f6 14 26 de 7d cf 8f b7 25 d1"
        "e7 46 75 d7 f5 32 7a 50 67 f3 67 b1 08 ec b6 7c",
    },

    {
        17*17*17, 0, 0, 32,
        "cb 55 2e 2e c7 7d 99 10 70 1d 57 8b 45 7d df 77"
        "2c 12 e3 22 e4 ee 7f e4 17 f9 2c 75 8f 0d 59 d0",
    },

    {
        17*17*17*17, 0, 0, 32,
        "87 01 04 5e 22 20 53 45 ff 4d da 05 55 5c bb 5c"
        "3a f1 a7 71 c2 b8 9b ae f3 7d b4 3d 99 98 b9 fe",
    },

    {
        17*17*17*17*17, 0, 0, 32,
        "84 4d 61 09 33 b1 b9 96 3c bd eb 5a e3 b6 b0 5c"
        "c7 cb d6 7c ee df 88 3e b6 78 a0 a8 e0 37 16 82",
    },

    {
        17*17*17*17*17*17, 0, 0, 32,
        "3c 39 07 82 a8 a4 e8 9f a6 36 7f 72 fe aa f1 32"
        "55 c8 d9 58 78 48 1d 3c d8 ce 85 f5 8e 88 0a f8",
    },

    {
        -0, 1, 0, 32,
        "fa b6 58 db 63 e9 4a 24 61 88 bf 7a f6 9a 13 30"
        "45 f4 6e e9 84 c5 6e 3c 33 28 ca af 1a a1 a5 83",
    },

    {
        -1, 41, 0, 32,
        "d8 48 c5 06 8c ed 73 6f 44 62 15 9b 98 67 fd 4c"
        "20 b8 08 ac c3 d5 bc 48 e0 b0 6b a0 a3 76 2e c4",
    },

    {
        -3, 41*41, 0, 32,
        "c3 89 e5 00 9a e5 71 20 85 4c 2e 8c 64 67 0a c0"
        "13 58 cf 4c 1b af 89 44 7a 72 42 34 dc 7c ed 74",
    },

    {
        -7, 41*41*41, 0, 32,
        "75 d2 f8 6a 2e 64 45 66 72 6b 4f bc fc 56 57 b9"
        "db cf 07 0c 7b 0d ca 06 45 0a b2 91 d7 44 3b cf",
    },

    { 0 }
}, *testptr = testvecs;

KangarooTwelve_t sh;
uint8_t bin[HASH_LEN];
uint8_t ref[HASH_LEN];
uint8_t msg[256];

#ifdef THREADS_CREW_H
static TCrew_t tcrew_shared;
#endif /* THREADS_CREW_H */

int main()
{
    int fails = 0;

    bufvec_t bv[2];
    long s, t;

#ifdef THREADS_CREW_H
    TCrew_Init(&tcrew_shared);
#endif /* THREADS_CREW_H */

    for(t=0; t<(long)sizeof(msg); t++) msg[t] = (uint8_t)t;

    while( testptr->ref )
    {
        KangarooTwelve_Init(&sh);
        /*XCTRL_FUNC(testptr->xof)(
            &sh, SHAKE_cSHAKE_customize,
            bv, 2, 0);*/

        // feed message. //

        if( testptr->mlen > 0 ) // pattern 0x00 to 0xfa
        {
            for(s=0,t=0; s<testptr->mlen; s+=t)
            {
                t = 251;
                if( s+t > testptr->mlen ) t = testptr->mlen - s;
                K12_Update4(&sh, msg, t, &tcrew_shared.funcstab);
            }
        }
        else // mlen times byte 0xff
        {
            for(t=testptr->mlen; t++<0; )
                K12_Update4(&sh, msg+255, 1, &tcrew_shared.funcstab);
        }

        // feed customization string. //

        if( testptr->clen > 0 ) // pattern 0x00 to 0xfa
        {
            for(s=0,t=0; s<testptr->clen; s+=t)
            {
                t = 251;
                if( s+t > testptr->clen ) t = testptr->clen - s;

                bv[0].dat = msg;
                bv[0].len = t;
                bv[1].buf = &tcrew_shared;
                K12_Xctrl(&sh, K12_cmd_Feed_CStr, bv, 2, 0);
            }
        }
        else // clen times byte 0xff
        {
            bv[0].dat = msg+255;
            bv[0].len = 1;
            bv[1].buf = &tcrew_shared;
            for(t=testptr->mlen; t++<0; )
                K12_Xctrl(&sh, K12_cmd_Feed_CStr, bv, 2, 0);
        }
        sh.clen = testptr->clen;

        K12_Final2(&sh, &tcrew_shared.funcstab);

        for(s=0,t=0; s<testptr->skip; s+=t)
        {
            t = HASH_LEN;
            if( s+t > testptr->skip ) t = testptr->skip - s;
            K12_Read4(&sh, bin, t, 0);
        }

        K12_Read4(&sh, bin, testptr->outlen, 0);

        scanhex(ref, testptr->outlen, testptr->ref);
        if( memcmp(bin, ref, testptr->outlen) )
        {
            fails++;
            printf("test %ld failed!\n", (long)(testptr - testvecs));
        }

        testptr++;
    }

#ifdef THREADS_CREW_H
    TCrew_Destroy(&tcrew_shared);
#endif /* THREADS_CREW_H */

    if( fails ) return EXIT_FAILURE; else
    {
        printf("All tests passed.\n");
        return EXIT_SUCCESS;
    }
}
