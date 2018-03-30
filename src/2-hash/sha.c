/* DannyNiu/NJF, 2018-02-05. Public Domain. */

#include "../0-datum/endian.h"
#include "../1-symm/fips-180.h"
#include "sha.h"

// SHA1 Definitions. 

void SHA1_Init(sha1_t *restrict sha)
{
    sha->finalized = 0;
    sha->len = 0;
    sha->H[0] = 0x67452301;
    sha->H[1] = 0xefcdab89;
    sha->H[2] = 0x98badcfe;
    sha->H[3] = 0x10325476;
    sha->H[4] = 0xc3d2e1f0;
    sha->filled = 0;
}

void SHA1_Update(sha1_t *restrict sha, const void *restrict data, size_t len)
{
    const uint8_t *ptr = data;
    
    // Msg must not be full when this loop enters.
    while(len)
    {
        sha->Msg8[sha->filled++] = *ptr++;
        len--;

        if( sha->filled == sizeof(sha->Msg8) ) {
            compressfunc_sha1(sha->H, sha->Msg32);
            sha->filled = 0;
        }
    }

    sha->len += (ptr - (const uint8_t *)data) * 8;
}

void SHA1_Final(sha1_t *restrict sha, void *restrict out)
{
    uint8_t *ptr = out;
    int i;

    // See [note:hash_h:1]. 
    if( sha->finalized ) goto finalized;
    
    if( sha->filled / sizeof(uint32_t) >= 14 )
    {
        sha->Msg8[sha->filled++] = 0x80;
        while( sha->filled < sizeof(sha->Msg8) )
            sha->Msg8[sha->filled++] = 0;
        compressfunc_sha1(sha->H, sha->Msg32);
        sha->filled = 0;

        while( sha->filled < sizeof(sha->Msg8) )
            sha->Msg8[sha->filled++] = 0;
        sha->filled = 0;
    }
    else
    {
        sha->Msg8[sha->filled++] = 0x80;
        while( sha->filled < sizeof(sha->Msg8) )
            sha->Msg8[sha->filled++] = 0;
        sha->filled = 0;
    }

    sha->Msg32[14] = htobe32(sha->len >> 32);
    sha->Msg32[15] = htobe32(sha->len);
    compressfunc_sha1(sha->H, sha->Msg32);
    for(i=0; i<5; i++)
        sha->Msg32[i] = htobe32(sha->H[i]);
    sha->finalized = 1;

finalized:
    for(i=0; i<20; i++) ptr[i] = sha->Msg8[i];
}

// SHA224, SHA256 Definitions. 

void sha256_update(sha256_t *restrict sha, const void *restrict data, size_t len)
{
    const uint8_t *ptr = data;
    
    // Msg must not be full when this loop enters.
    while(len)
    {
        sha->Msg8[sha->filled++] = *ptr++;
        len--;

        if( sha->filled == sizeof(sha->Msg8) ) {
            compressfunc_sha256(sha->H, sha->Msg32);
            sha->filled = 0;
        }
    }

    sha->len += (ptr - (const uint8_t *)data) * 8;
}

static void sha256_final(sha256_t *restrict sha)
{
    // See [note:hash_h:1]. 
    if( sha->finalized ) return;
    
    if( sha->filled / sizeof(uint32_t) >= 14 )
    {
        sha->Msg8[sha->filled++] = 0x80;
        while( sha->filled < sizeof(sha->Msg8) )
            sha->Msg8[sha->filled++] = 0;
        compressfunc_sha256(sha->H, sha->Msg32);
        sha->filled = 0;

        while( sha->filled < sizeof(sha->Msg8) )
            sha->Msg8[sha->filled++] = 0;
        sha->filled = 0;
    }
    else
    {
        sha->Msg8[sha->filled++] = 0x80;
        while( sha->filled < sizeof(sha->Msg8) )
            sha->Msg8[sha->filled++] = 0;
        sha->filled = 0;
    }

    sha->Msg32[14] = htobe32(sha->len >> 32);
    sha->Msg32[15] = htobe32(sha->len);
    compressfunc_sha256(sha->H, sha->Msg32);
    for(int i=0; i<8; i++)
        sha->Msg32[i] = htobe32(sha->H[i]);
    sha->finalized = 1;
}

void SHA224_Init(sha224_t *restrict sha)
{
    sha->finalized = 0;
    sha->len = 0;
    sha->H[0] = 0xc1059ed8;
    sha->H[1] = 0x367cd507;
    sha->H[2] = 0x3070dd17;
    sha->H[3] = 0xf70e5939;
    sha->H[4] = 0xffc00b31;
    sha->H[5] = 0x68581511;
    sha->H[6] = 0x64f98fa7;
    sha->H[7] = 0xbefa4fa4;
    sha->filled = 0;
}

void SHA224_Final(sha224_t *restrict sha, void *restrict out)
{
    uint8_t *ptr = out;
    int i;

    sha256_final(sha);
    for(i=0; i<28; i++) ptr[i] = sha->Msg8[i];
}

void SHA256_Init(sha256_t *restrict sha)
{
    sha->finalized = 0;
    sha->len = 0;
    sha->H[0] = 0x6a09e667;
    sha->H[1] = 0xbb67ae85;
    sha->H[2] = 0x3c6ef372;
    sha->H[3] = 0xa54ff53a;
    sha->H[4] = 0x510e527f;
    sha->H[5] = 0x9b05688c;
    sha->H[6] = 0x1f83d9ab;
    sha->H[7] = 0x5be0cd19;
    sha->filled = 0;
}

void SHA256_Final(sha256_t *restrict sha, void *restrict out)
{
    uint8_t *ptr = out;
    int i;

    sha256_final(sha);
    for(i=0; i<32; i++) ptr[i] = sha->Msg8[i];
}

// SHA384, SHA512 Definitions. 

void sha512_update(sha512_t *restrict sha, const void *restrict data, size_t len)
{
    const uint8_t *ptr = data;
    
    // Msg must not be full when this loop enters.
    while(len)
    {
        sha->Msg8[sha->filled++] = *ptr++;
        len--;

        if( sha->filled == sizeof(sha->Msg8) ) {
            compressfunc_sha512(sha->H, sha->Msg64);
            sha->filled = 0;
        }
    }

    sha->len += (ptr - (const uint8_t *)data) * 8;
}

static void sha512_final(sha512_t *restrict sha)
{
    // See [note:hash_h:1]. 
    if( sha->finalized ) return;
    
    if( sha->filled / sizeof(uint64_t) >= 14 )
    {
        sha->Msg8[sha->filled++] = 0x80;
        while( sha->filled < sizeof(sha->Msg8) )
            sha->Msg8[sha->filled++] = 0;
        compressfunc_sha512(sha->H, sha->Msg64);
        sha->filled = 0;

        while( sha->filled < sizeof(sha->Msg8) )
            sha->Msg8[sha->filled++] = 0;
        sha->filled = 0;
    }
    else
    {
        sha->Msg8[sha->filled++] = 0x80;
        while( sha->filled < sizeof(sha->Msg8) )
            sha->Msg8[sha->filled++] = 0;
        sha->filled = 0;
    }

    // Known Bug: Streaming longer than 2^64 currently not supported. 
    sha->Msg64[14] = htobe64(0);
    sha->Msg64[15] = htobe64(sha->len);
    compressfunc_sha512(sha->H, sha->Msg64);
    for(int i=0; i<8; i++)
        sha->Msg64[i] = htobe64(sha->H[i]);
    sha->finalized = 1;
}

void SHA384_Init(sha384_t *restrict sha)
{
    sha->finalized = 0;
    sha->len = 0;
    sha->H[0] = 0xcbbb9d5dc1059ed8;
    sha->H[1] = 0x629a292a367cd507;
    sha->H[2] = 0x9159015a3070dd17;
    sha->H[3] = 0x152fecd8f70e5939;
    sha->H[4] = 0x67332667ffc00b31;
    sha->H[5] = 0x8eb44a8768581511;
    sha->H[6] = 0xdb0c2e0d64f98fa7;
    sha->H[7] = 0x47b5481dbefa4fa4;
    sha->filled = 0;
}

void SHA384_Final(sha384_t *restrict sha, void *restrict out)
{
    uint8_t *ptr = out;
    int i;

    sha512_final(sha);
    for(i=0; i<48; i++) ptr[i] = sha->Msg8[i];
}

void SHA512_Init(sha512_t *restrict sha)
{
    sha->finalized = 0;
    sha->len = 0;
    sha->H[0] = 0x6a09e667f3bcc908;
    sha->H[1] = 0xbb67ae8584caa73b;
    sha->H[2] = 0x3c6ef372fe94f82b;
    sha->H[3] = 0xa54ff53a5f1d36f1;
    sha->H[4] = 0x510e527fade682d1;
    sha->H[5] = 0x9b05688c2b3e6c1f;
    sha->H[6] = 0x1f83d9abfb41bd6b;
    sha->H[7] = 0x5be0cd19137e2179;
    sha->filled = 0;
}

void SHA512_Final(sha512_t *restrict sha, void *restrict out)
{
    uint8_t *ptr = out;
    int i;

    sha512_final(sha);
    for(i=0; i<64; i++) ptr[i] = sha->Msg8[i];
}

intptr_t iSHA1(int q){ return _iSHA1(q); }
intptr_t iSHA224(int q){ return _iSHA224(q); }
intptr_t iSHA256(int q){ return _iSHA256(q); }
intptr_t iSHA384(int q){ return _iSHA384(q); }
intptr_t iSHA512(int q){ return _iSHA512(q); }
