/* DannyNiu/NJF, 2018-02-05. Public Domain. */

#ifndef MySuiteA_sha_h
#define MySuiteA_sha_h 1

// References: src/notes.txt: "SHA-1, SHA-256, etc.". 

#include "../mysuitea-common.h"

typedef struct sha1_context {
    int         finalized;
    unsigned    filled;
    uint64_t    len;
    uint32_t    H[5];
    uint32_t    pad_H6; // to silence a warning. 
    union {
        uint32_t    Msg32[16];
        uint8_t     Msg8[64];
    };
} sha1_t; // only included for completeness, deprecated. 

void SHA1_Init(sha1_t *restrict sha);
void SHA1_Update(sha1_t *restrict sha, void const *restrict data, size_t len);
void SHA1_Final(sha1_t *restrict sha, void *restrict out, size_t t);

typedef struct sha256_context {
    int         finalized;
    unsigned    filled;
    uint64_t    len;
    uint32_t    H[8];
    union {
        uint32_t    Msg32[16];
        uint8_t     Msg8[64];
    };
} sha224_t, sha256_t;

void sha256_update(sha256_t *restrict sha, void const *restrict data, size_t len);
#define SHA224_Update sha256_update
#define SHA256_Update sha256_update
void SHA224_Init(sha224_t *restrict sha);
void SHA256_Init(sha256_t *restrict sha);
void SHA224_Final(sha224_t *restrict sha, void *restrict out, size_t t);
void SHA256_Final(sha256_t *restrict sha, void *restrict out, size_t t);

typedef struct sha512_context {
    int         finalized;
    unsigned    filled;
    uint64_t    len;
    uint64_t    H[8];
    union {
        uint64_t    Msg64[16];
        uint8_t     Msg8[128];
    };
} sha384_t, sha512_t;

void sha512_update(sha512_t *restrict sha, void const *restrict data, size_t len);
#define SHA384_Update sha512_update
#define SHA512_Update sha512_update
void SHA384_Init(sha384_t *restrict sha);
void SHA512_Init(sha512_t *restrict sha);
void SHA384_Final(sha384_t *restrict sha, void *restrict out, size_t t);
void SHA512_Final(sha512_t *restrict sha, void *restrict out, size_t t);

#define cSHA1(q) (                                      \
        q==outBytes ? 20 :                              \
        q==blockBytes ? 64 :                            \
        q==contextBytes ? sizeof(struct sha1_context) : \
        q==InitFunc   ? (uintmax_t)SHA1_Init :          \
        q==UpdateFunc ? (uintmax_t)SHA1_Update :        \
        q==FinalFunc  ? (uintmax_t)SHA1_Final :         \
        0)
#define cSHA224(q) (                                            \
        q==outBytes ? 28 :                                      \
        q==blockBytes ? 64 :                                    \
        q==contextBytes ? sizeof(struct sha256_context) :       \
        q==InitFunc   ? (uintmax_t)SHA224_Init :                \
        q==UpdateFunc ? (uintmax_t)SHA224_Update :              \
        q==FinalFunc  ? (uintmax_t)SHA224_Final :               \
        0)
#define cSHA256(q) (                                            \
        q==outBytes ? 32 :                                      \
        q==blockBytes ? 64 :                                    \
        q==contextBytes ? sizeof(struct sha256_context) :       \
        q==InitFunc   ? (uintmax_t)SHA256_Init :                \
        q==UpdateFunc ? (uintmax_t)SHA256_Update :              \
        q==FinalFunc  ? (uintmax_t)SHA256_Final :               \
        0)
#define cSHA384(q) (                                            \
        q==outBytes ? 48 :                                      \
        q==blockBytes ? 128 :                                   \
        q==contextBytes ? sizeof(struct sha512_context) :       \
        q==InitFunc   ? (uintmax_t)SHA384_Init :                \
        q==UpdateFunc ? (uintmax_t)SHA384_Update :              \
        q==FinalFunc  ? (uintmax_t)SHA384_Final :               \
        0)
#define cSHA512(q) (                                            \
        q==outBytes ? 64 :                                      \
        q==blockBytes ? 128 :                                   \
        q==contextBytes ? sizeof(struct sha512_context) :       \
        q==InitFunc   ? (uintmax_t)SHA512_Init :                \
        q==UpdateFunc ? (uintmax_t)SHA512_Update :              \
        q==FinalFunc  ? (uintmax_t)SHA512_Final :               \
        0)

uintmax_t iSHA1(int q);
uintmax_t iSHA224(int q);
uintmax_t iSHA256(int q);
uintmax_t iSHA384(int q);
uintmax_t iSHA512(int q);

#endif
