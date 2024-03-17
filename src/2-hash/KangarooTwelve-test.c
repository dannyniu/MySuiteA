/* DannyNiu/NJF, 2022-09-08. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "KangarooTwelve.h"
#include "../1-oslib/TCrew.h"

#include "../test-utils.c.h"

#define HASH_LEN 128

static const struct {
    void (*initfunc)(K12_Ctx_t *);
    long mlen, clen, skip, outlen;
    const char *ref;
} testvecs[] = {
    {
        KT128_Init,
        0, 0, 0, 32,
        "1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca 1b 37 51"
        "3c 08 03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5",
    },

    {
        KT128_Init,
        0, 0, 0, 64,
        "1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca 1b 37 51"
        "3c 08 03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5"
        "42 69 c0 56 b8 c8 2e 48 27 60 38 b6 d2 92 96 6c"
        "c0 7a 3d 46 45 27 2e 31 ff 38 50 81 39 eb 0a 71",
    },

    {
        KT128_Init,
        0, 0, 10000, 32,
        "e8 dc 56 36 42 f7 22 8c 84 68 4c 89 84 05 d3 a8"
        "34 79 91 58 c0 79 b1 28 80 27 7a 1d 28 e2 ff 6d",
    },

    {
        KT128_Init,
        1, 0, 0, 32,
        "2b da 92 45 0e 8b 14 7f 8a 7c b6 29 e7 84 a0 58"
        "ef ca 7c f7 d8 21 8e 02 d3 45 df aa 65 24 4a 1f",
    },

    {
        KT128_Init,
        17, 0, 0, 32,
        "6b f7 5f a2 23 91 98 db 47 72 e3 64 78 f8 e1 9b"
        "0f 37 12 05 f6 a9 a9 3a 27 3f 51 df 37 12 28 88",
    },

    {
        KT128_Init,
        17*17, 0, 0, 32,
        "0c 31 5e bc de db f6 14 26 de 7d cf 8f b7 25 d1"
        "e7 46 75 d7 f5 32 7a 50 67 f3 67 b1 08 ec b6 7c",
    },

    {
        KT128_Init,
        17*17*17, 0, 0, 32,
        "cb 55 2e 2e c7 7d 99 10 70 1d 57 8b 45 7d df 77"
        "2c 12 e3 22 e4 ee 7f e4 17 f9 2c 75 8f 0d 59 d0",
    },

    {
        KT128_Init,
        17*17*17*17, 0, 0, 32,
        "87 01 04 5e 22 20 53 45 ff 4d da 05 55 5c bb 5c"
        "3a f1 a7 71 c2 b8 9b ae f3 7d b4 3d 99 98 b9 fe",
    },

    {
        KT128_Init,
        17*17*17*17*17, 0, 0, 32,
        "84 4d 61 09 33 b1 b9 96 3c bd eb 5a e3 b6 b0 5c"
        "c7 cb d6 7c ee df 88 3e b6 78 a0 a8 e0 37 16 82",
    },

    {
        KT128_Init,
        17*17*17*17*17*17, 0, 0, 32,
        "3c 39 07 82 a8 a4 e8 9f a6 36 7f 72 fe aa f1 32"
        "55 c8 d9 58 78 48 1d 3c d8 ce 85 f5 8e 88 0a f8",
    },

    {
        KT128_Init,
        -0, 1, 0, 32,
        "fa b6 58 db 63 e9 4a 24 61 88 bf 7a f6 9a 13 30"
        "45 f4 6e e9 84 c5 6e 3c 33 28 ca af 1a a1 a5 83",
    },

    {
        KT128_Init,
        -1, 41, 0, 32,
        "d8 48 c5 06 8c ed 73 6f 44 62 15 9b 98 67 fd 4c"
        "20 b8 08 ac c3 d5 bc 48 e0 b0 6b a0 a3 76 2e c4",
    },

    {
        KT128_Init,
        -3, 41*41, 0, 32,
        "c3 89 e5 00 9a e5 71 20 85 4c 2e 8c 64 67 0a c0"
        "13 58 cf 4c 1b af 89 44 7a 72 42 34 dc 7c ed 74",
    },

    {
        KT128_Init,
        -7, 41*41*41, 0, 32,
        "75 d2 f8 6a 2e 64 45 66 72 6b 4f bc fc 56 57 b9"
        "db cf 07 0c 7b 0d ca 06 45 0a b2 91 d7 44 3b cf",
    },

    {
        KT128_Init,
        8191, 0, 0, 32,
        "1B 57 76 36 F7 23 64 3E 99 0C C7 D6 A6 59 83 74"
        "36 FD 6A 10 36 26 60 0E B8 30 1C D1 DB E5 53 D6",
    },

    {
        KT128_Init,
        8192, 0, 0, 32,
        "48 F2 56 F6 77 2F 9E DF B6 A8 B6 61 EC 92 DC 93"
        "B9 5E BD 05 A0 8A 17 B3 9A E3 49 08 70 C9 26 C3",
    },

    {
        KT128_Init,
        8192, 8189, 0, 32,
        "3E D1 2F 70 FB 05 DD B5 86 89 51 0A B3 E4 D2 3C"
        "6C 60 33 84 9A A0 1E 1D 8C 22 0A 29 7F ED CD 0B",
    },

    {
        KT128_Init,
        8192, 8190, 0, 32,
        "6A 7C 1B 6A 5C D0 D8 C9 CA 94 3A 4A 21 6C C6 46"
        "04 55 9A 2E A4 5F 78 57 0A 15 25 3D 67 BA 00 AE",
    },

    {
        KT256_Init,
        0, 0, 0, 64,
        "B2 3D 2E 9C EA 9F 49 04 E0 2B EC 06 81 7F C1 0C"
        "E3 8C E8 E9 3E F4 C8 9E 65 37 07 6A F8 64 64 04"
        "E3 E8 B6 81 07 B8 83 3A 5D 30 49 0A A3 34 82 35"
        "3F D4 AD C7 14 8E CB 78 28 55 00 3A AE BD E4 A9",
    },

    {
        KT256_Init,
        0, 0, 0, 128,
        "B2 3D 2E 9C EA 9F 49 04 E0 2B EC 06 81 7F C1 0C"
        "E3 8C E8 E9 3E F4 C8 9E 65 37 07 6A F8 64 64 04"
        "E3 E8 B6 81 07 B8 83 3A 5D 30 49 0A A3 34 82 35"
        "3F D4 AD C7 14 8E CB 78 28 55 00 3A AE BD E4 A9"
        "B0 92 53 19 D8 EA 1E 12 1A 60 98 21 EC 19 EF EA"
        "89 E6 D0 8D AE E1 66 2B 69 C8 40 28 9F 18 8B A8"
        "60 F5 57 60 B6 1F 82 11 4C 03 0C 97 E5 17 84 49"
        "60 8C CD 2C D2 D9 19 FC 78 29 FF 69 93 1A C4 D0",
    },

    {
        KT256_Init,
        0, 0, 10000, 64,
        "AD 4A 1D 71 8C F9 50 50 67 09 A4 C3 33 96 13 9B"
        "44 49 04 1F C7 9A 05 D6 8D A3 5F 1E 45 35 22 E0"
        "56 C6 4F E9 49 58 E7 08 5F 29 64 88 82 59 B9 93"
        "27 52 F3 CC D8 55 28 8E FE E5 FC BB 8B 56 30 69",
    },

    {
        KT256_Init,
        1, 0, 0, 64,
        "0D 00 5A 19 40 85 36 02 17 12 8C F1 7F 91 E1 F7"
        "13 14 EF A5 56 45 39 D4 44 91 2E 34 37 EF A1 7F"
        "82 DB 6F 6F FE 76 E7 81 EA A0 68 BC E0 1F 2B BF"
        "81 EA CB 98 3D 72 30 F2 FB 02 83 4A 21 B1 DD D0",
    },

    {
        KT256_Init,
        17, 0, 0, 64,
        "1B A3 C0 2B 1F C5 14 47 4F 06 C8 97 99 78 A9 05"
        "6C 84 83 F4 A1 B6 3D 0D CC EF E3 A2 8A 2F 32 3E"
        "1C DC CA 40 EB F0 06 AC 76 EF 03 97 15 23 46 83"
        "7B 12 77 D3 E7 FA A9 C9 65 3B 19 07 50 98 52 7B",
    },

    {
        KT256_Init,
        17*17, 0, 0, 64,
        "DE 8C CB C6 3E 0F 13 3E BB 44 16 81 4D 4C 66 F6"
        "91 BB F8 B6 A6 1E C0 A7 70 0F 83 6B 08 6C B0 29"
        "D5 4F 12 AC 71 59 47 2C 72 DB 11 8C 35 B4 E6 AA"
        "21 3C 65 62 CA AA 9D CC 51 89 59 E6 9B 10 F3 BA",
    },

    {
        KT256_Init,
        17*17*17, 0, 0, 64,
        "64 7E FB 49 FE 9D 71 75 00 17 1B 41 E7 F1 1B D4"
        "91 54 44 43 20 99 97 CE 1C 25 30 D1 5E B1 FF BB"
        "59 89 35 EF 95 45 28 FF C1 52 B1 E4 D7 31 EE 26"
        "83 68 06 74 36 5C D1 91 D5 62 BA E7 53 B8 4A A5",
    },

    {
        KT256_Init,
        17*17*17*17, 0, 0, 64,
        "B0 62 75 D2 84 CD 1C F2 05 BC BE 57 DC CD 3E C1"
        "FF 66 86 E3 ED 15 77 63 83 E1 F2 FA 3C 6A C8 F0"
        "8B F8 A1 62 82 9D B1 A4 4B 2A 43 FF 83 DD 89 C3"
        "CF 1C EB 61 ED E6 59 76 6D 5C CF 81 7A 62 BA 8D",
    },

    {
        KT256_Init,
        17*17*17*17*17, 0, 0, 64,
        "94 73 83 1D 76 A4 C7 BF 77 AC E4 5B 59 F1 45 8B"
        "16 73 D6 4B CD 87 7A 7C 66 B2 66 4A A6 DD 14 9E"
        "60 EA B7 1B 5C 2B AB 85 8C 07 4D ED 81 DD CE 2B"
        "40 22 B5 21 59 35 C0 D4 D1 9B F5 11 AE EB 07 72",
    },

    {
        KT256_Init,
        17*17*17*17*17*17, 0, 0, 64,
        "06 52 B7 40 D7 8C 5E 1F 7C 8D CC 17 77 09 73 82"
        "76 8B 7F F3 8F 9A 7A 20 F2 9F 41 3B B1 B3 04 5B"
        "31 A5 57 8F 56 8F 91 1E 09 CF 44 74 6D A8 42 24"
        "A5 26 6E 96 A4 A5 35 E8 71 32 4E 4F 9C 70 04 DA",
    },

    {
        KT256_Init,
        0, 1, 0, 64,
        "92 80 F5 CC 39 B5 4A 5A 59 4E C6 3D E0 BB 99 37"
        "1E 46 09 D4 4B F8 45 C2 F5 B8 C3 16 D7 2B 15 98"
        "11 F7 48 F2 3E 3F AB BE 5C 32 26 EC 96 C6 21 86"
        "DF 2D 33 E9 DF 74 C5 06 9C EE CB B4 DD 10 EF F6",
    },

    {
        KT256_Init,
        -1, 41, 0, 64,
        "47 EF 96 DD 61 6F 20 09 37 AA 78 47 E3 4E C2 FE"
        "AE 80 87 E3 76 1D C0 F8 C1 A1 54 F5 1D C9 CC F8"
        "45 D7 AD BC E5 7F F6 4B 63 97 22 C6 A1 67 2E 3B"
        "F5 37 2D 87 E0 0A FF 89 BE 97 24 07 56 99 88 53",
    },

    {
        KT256_Init,
        -3, 41*41, 0, 64,
        "3B 48 66 7A 50 51 C5 96 6C 53 C5 D4 2B 95 DE 45"
        "1E 05 58 4E 78 06 E2 FB 76 5E DA 95 90 74 17 2C"
        "B4 38 A9 E9 1D DE 33 7C 98 E9 C4 1B ED 94 C4 E0"
        "AE F4 31 D0 B6 4E F2 32 4F 79 32 CA A6 F5 49 69",
    },

    {
        KT256_Init,
        -7, 41*41*41, 0, 64,
        "E0 91 1C C0 00 25 E1 54 08 31 E2 66 D9 4A DD 9B"
        "98 71 21 42 B8 0D 26 29 E6 43 AA C4 EF AF 5A 3A"
        "30 A8 8C BF 4A C2 A9 1A 24 32 74 30 54 FB CC 98"
        "97 67 0E 86 BA 8C EC 2F C2 AC E9 C9 66 36 97 24",
    },

    {
        KT256_Init,
        8191, 0, 0, 64,
        "30 81 43 4D 93 A4 10 8D 8D 8A 33 05 B8 96 82 CE"
        "BE DC 7C A4 EA 8A 3C E8 69 FB B7 3C BE 4A 58 EE"
        "F6 F2 4D E3 8F FC 17 05 14 C7 0E 7A B2 D0 1F 03"
        "81 26 16 E8 63 D7 69 AF B3 75 31 93 BA 04 5B 20",
    },

    {
        KT256_Init,
        8192, 0, 0, 64,
        "C6 EE 8E 2A D3 20 0C 01 8A C8 7A AA 03 1C DA C2"
        "21 21 B4 12 D0 7D C6 E0 DC CB B5 34 23 74 7E 9A"
        "1C 18 83 4D 99 DF 59 6C F0 CF 4B 8D FA FB 7B F0"
        "2D 13 9D 0C 90 35 72 5A DC 1A 01 B7 23 0A 41 FA",
    },

    {
        KT256_Init,
        8192, 8189, 0, 64,
        "74 E4 78 79 F1 0A 9C 5D 11 BD 2D A7 E1 94 FE 57"
        "E8 63 78 BF 3C 3F 74 48 EF F3 C5 76 A0 F1 8C 5C"
        "AA E0 99 99 79 51 20 90 A7 F3 48 AF 42 60 D4 DE"
        "3C 37 F1 EC AF 8D 2C 2C 96 C1 D1 6C 64 B1 24 96",
    },

    {
        KT256_Init,
        8192, 8190, 0, 64,
        "F4 B5 90 8B 92 9F FE 01 E0 F7 9E C2 F2 12 43 D4"
        "1A 39 6B 2E 73 03 A6 AF 1D 63 99 CD 6C 7A 0A 2D"
        "D7 C4 F6 07 E8 27 7F 9C 9B 1C B4 AB 9D DC 59 D4"
        "B9 2D 1F C7 55 84 41 F1 83 2C 32 79 A4 24 1B 8B",
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
        testptr->initfunc(&sh);

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
        // else printf("test %ld passes!\n", (long)(testptr - testvecs));

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
