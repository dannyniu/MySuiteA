/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#ifndef MySuiteA_mysuitea_common_h
#define MySuiteA_mysuitea_common_h 1

#include <limits.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#define xglue(a,b) a##b
#define glue(a,b) xglue(a,b)

// Each primitive instance shall define
// 1. a function compatible with the type (uintmax_t(*)(int)),
// 2. a function-like macro that evaluates to some integer types that's
//    large enough to hold pointers,
// that when evaluated in run-time or compile time,
// yields relevant information associated with particular primitive.
//
// Both the function and the function like macro takes a single
// argument `q' that is one of the constants enumerated below.
//
// The name of the function shall be the name of the primitive
// prefixed with a single "i"; the name of the macro shall be
// the name of the primitive prefixed with a single "c".

// 2020-11-21:
// Per https://stackoverflow.com/q/64894785
// ``uintptr_t'' is changed to ``uintmax_t'', and the
// following static assertion is added. 

_Static_assert(
    sizeof(uintmax_t) >= sizeof(void (*)(void)),
    "Expectation on the compilation environment didn't hold!");

enum {
    // Applicable to
    // 1.) Primitives whose output length are fixed and constant. 
    //
    // For hash functions, this is the length of the digest in bytes.
    //
    outBytes,

    // Applicable to
    // 1.) Fixed-length keyed or unkeyed permutations.
    // 2.) Iterated bufferred processing primitives. 
    //
    blockBytes,

    // Applicable to
    // 1.) All keyed primitives.
    //
    // If keyBytes == 0, then keyBytesMax specifies the
    // maximum acceptable key length:
    // - a value of 0 specifies that the primitive is unkeyed,
    // - a value of ((size_t)-1) specifies that such limit
    //   doesn't exist for that particular instance.
    //
    keyBytes, keyBytesMax,

    // Applicable to
    // 1.) All iterated keyed permutation with at least 1 iteration.
    //
    keyschedBytes,

    // Applicable to
    // 1.) Primitives reusing working variables for invocations.
    // 2.) Primitives saving working varibles for later resumption. 
    //
    contextBytes,

    // Applicable to
    // 1.) AEAD.
    //
    ivBytes, tagBytes, 

    // Block Cipher Interfaces //
    EncFunc, DecFunc, KschdFunc,

    // Permutation Interfaces //
    PermuteFunc,

    // Keyed Context Initialization Function (AEAD, HMAC, etc.) //
    KInitFunc,
    
    // Hash & XOF Functions //
    InitFunc,
    UpdateFunc, WriteFunc=UpdateFunc,
    FinalFunc, XofFinalFunc,
    ReadFunc,

    // AEAD Functions //
    AEncFunc, ADecFunc, 
    
    // Information macros evaluates to 0
    // for queries not applicable to them. 
};

// Aliases additions for PRNG/DRBG.
enum {
    seedBytes     = keyBytes,
    seedBytesMax  = keyBytesMax,
    InstInitFunc  = KInitFunc,
    ReseedFunc    = WriteFunc,
    GenFunc       = ReadFunc,
};

typedef void (*EncFunc_t)(void const *in, void *out, void const *restrict w);
typedef void (*DecFunc_t)(void const *in, void *out, void const *restrict w);
typedef void (*KschdFunc_t)(void const *restrict key, void *restrict w);

typedef void (*PermuteFunc_t)(void const *in, void *out);

// Returns ``x'' on success, or ``NULL'' with invalid ``klen''.
typedef void *(*KInitFunc_t)(void *restrict x,
                             void const *restrict k,
                             size_t klen);
typedef void (*InitFunc_t)(void *restrict x);

typedef void (*UpdateFunc_t)(void *restrict x,
                             void const *restrict data, 
                             size_t len);
typedef UpdateFunc_t WriteFunc_t;

typedef void (*FinalFunc_t)(void *restrict x, void *restrict out, size_t t);
typedef void (*XFinalFunc_t)(void *restrict x);
typedef void (*ReadFunc_t)(void *restrict x,
                           void *restrict data,
                           size_t len);

// AEAD cipher taking data all-at-once.
typedef void (*AEncFunc_t)(void *restrict x,
                           void const *restrict iv,
                           size_t alen, void const *aad,
                           size_t len, void const *in, void *out,
                           size_t tlen, void *T);
// returns ``out'' on success and ``NULL'' on decryption failure.
typedef void *(*ADecFunc_t)(void *restrict x,
                            void const *restrict iv,
                            size_t alen, void const *aad,
                            size_t len, void const *in, void *out,
                            size_t tlen, void const *T);

// Alias additions for PRNG/DRBG.
typedef KInitFunc_t     InstInitFunc_t;
typedef WriteFunc_t     ReseedFunc_t;
typedef ReadFunc_t      GenFunc_t;

// Because `obj' can be an identifier naming a macro
// as well as a pointer to a function , we have to
// make sure that `obj' is not parenthesized so that
// macro expansion won't be suppressed.

#define OUT_BYTES(obj)      ((size_t)(obj(outBytes)))
#define BLOCK_BYTES(obj)    ((size_t)(obj(blockBytes)))
#define KEY_BYTES(obj)      ((size_t)(obj(keyBytes)))
#define KEY_BYTES_MAX(obj)  ((size_t)(obj(keyBytesMax)))
#define KSCHD_BYTES(obj)    ((size_t)(obj(keyschedBytes)))
#define CTX_BYTES(obj)      ((size_t)(obj(contextBytes)))
#define IV_BYTES(obj)       ((size_t)(obj(ivBytes)))
#define TAG_BYTES(obj)      ((size_t)(obj(tagBytes)))

// In case C doesn't expand nested macro.
#define CTX_BYTES_1(obj)    ((size_t)(obj(contextBytes)))
#define CTX_BYTES_2(obj)    ((size_t)(obj(contextBytes)))
#define CTX_BYTES_3(obj)    ((size_t)(obj(contextBytes)))
#define CTX_BYTES_4(obj)    ((size_t)(obj(contextBytes)))
#define CTX_BYTES_5(obj)    ((size_t)(obj(contextBytes)))
#define CTX_BYTES_6(obj)    ((size_t)(obj(contextBytes)))
#define CTX_BYTES_7(obj)    ((size_t)(obj(contextBytes)))
#define CTX_BYTES_8(obj)    ((size_t)(obj(contextBytes)))
#define CTX_BYTES_9(obj)    ((size_t)(obj(contextBytes)))

#define ENC_FUNC(obj)       ((EncFunc_t)(obj(EncFunc)))
#define DEC_FUNC(obj)       ((DecFunc_t)(obj(DecFunc)))
#define KSCHD_FUNC(obj)     ((KschdFunc_t)(obj(KschdFunc)))

#define PERMUTE_FUNC(obj)   ((PermuteFunc_t)(obj(PermuteFunc)))

#define INIT_FUNC(obj)      ((InitFunc_t)(obj(InitFunc)))
#define UPDATE_FUNC(obj)    ((UpdateFunc_t)(obj(UpdateFunc)))
#define WRITE_FUNC(obj)     ((WriteFunc_t)(obj(WriteFunc)))
#define FINAL_FUNC(obj)     ((FinalFunc_t)(obj(FinalFunc)))
#define XFINAL_FUNC(obj)    ((XFinalFunc_t)(obj(XofFinalFunc)))
#define READ_FUNC(obj)      ((ReadFunc_t)(obj(ReadFunc)))

#define KINIT_FUNC(obj)     ((KInitFunc_t)(obj(KInitFunc)))

#define AENC_FUNC(obj)      ((AEncFunc_t)(obj(AEncFunc)))
#define ADEC_FUNC(obj)      ((ADecFunc_t)(obj(ADecFunc)))

// Aliases additions for PRNG/DRBG.
#define SEED_BYTES(obj)     ((size_t)(obj(seedBytes)))
#define SEED_BYTES_MAX(obj) ((size_t)(obj(seedBytesMax)))
#define INST_INIT_FUNC(obj) ((InstInitFunc_t)(obj(InstInitFunc)))
#define RESEED_FUNC(obj)    ((ReseedFunc_t)(obj(ReseedFunc)))
#define GEN_FUNC(obj)       ((GenFunc_t)(obj(GenFunc)))

#define ERASE_STATES(buf, len)                          \
    do {                                                \
        char volatile *ba = (void volatile *)(buf);     \
        size_t l = (size_t)(len);                       \
        for(size_t i=0; i<l; i++) ba[i] = 0;            \
    } while(0)
    
#endif /* MySuiteA_mysuitea_common_h */
