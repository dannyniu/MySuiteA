/* DannyNiu/NJF, 2022-08-17. Public Domain. */

#define qround_word(a, b, c, d, x, y)                           \
    {                                                           \
        a += b + le32toh(x); d ^= a; d = (d>>16)|(d<<16);       \
        c += d             ; b ^= c; b = (b>>12)|(b<<20);       \
        a += b + le32toh(y); d ^= a; d = (d>> 8)|(d<<24);       \
        c += d             ; b ^= c; b = (b>> 7)|(b<<25);       \
    }

#define qround_long(a, b, c, d, x, y)                           \
    {                                                           \
        a += b + le64toh(x); d ^= a; d = (d>>32)|(d<<32);       \
        c += d             ; b ^= c; b = (b>>24)|(b<<40);       \
        a += b + le64toh(y); d ^= a; d = (d>>16)|(d<<48);       \
        c += d             ; b ^= c; b = (b>>63)|(b<< 1);       \
    }

#define IV0 0x6a09e667
#define IV1 0xbb67ae85
#define IV2 0x3c6ef372
#define IV3 0xa54ff53a
#define IV4 0x510e527f
#define IV5 0x9b05688c
#define IV6 0x1f83d9ab
#define IV7 0x5be0cd19

#define IV0l 0x6a09e667f3bcc908
#define IV1l 0xbb67ae8584caa73b
#define IV2l 0x3c6ef372fe94f82b
#define IV3l 0xa54ff53a5f1d36f1
#define IV4l 0x510e527fade682d1
#define IV5l 0x9b05688c2b3e6c1f
#define IV6l 0x1f83d9abfb41bd6b
#define IV7l 0x5be0cd19137e2179
