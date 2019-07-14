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
// 1. a function compatible with the type (uintptr_t(*)(int)),
// 2. a function-like macro that evaluates tox integer types -
//    sometimes large enough to hold pointers,
// that when evaluated in run-time or compile time,
// yields relevant information associated with particular primitive.
//
// Both the function and the function like macro takes a single
// argument `q' that is one of the constants enumerated below.
//
// The name of the function shall be the name of the primitive
// prefixed with a single "i"; the name of the macro shall be
// that of the function prefixed with a single <underscore> ("_"). 

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
    keyBytes,

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

    // Hash & XOF Functions //
    InitFunc,
    UpdateFunc, WriteFunc=UpdateFunc,
    FinalFunc, XofFinalFunc,
    ReadFunc,

    // Keyed Context Initialization Function (AEAD, HMAC, etc.) //
    KInitFunc,
    
    // AEAD Functions //
    AEncFunc, ADecFunc, 
    
    // Information macros evaluates to -1
    // for queries not applicable to them. 
};

typedef void (*EncFunc_t)(const void *in, void *out, void *restrict w);
typedef void (*DecFunc_t)(const void *in, void *out, void *restrict w);
typedef void (*KschdFunc_t)(const void *restrict key, void *restrict w);

typedef void (*PermuteFunc_t)(const void *in, void *out);

typedef void (*InitFunc_t)(void *restrict x);
typedef void (*UpdateFunc_t)(void *restrict x,
                             const void *restrict data, 
                             size_t len);
typedef UpdateFunc_t WriteFunc_t;

typedef void (*FinalFunc_t)(void *restrict x, void *restrict out);
typedef void (*XFinalFunc_t)(void *restrict x);
typedef void (*ReadFunc_t)(void *restrict x,
                           void *restrict data,
                           size_t len);

typedef void (*KInitFunc_t)(void *restrict x, const void *restrict k);
typedef void (*AEncFunc_t)(void *restrict x,
                           const void *restrict iv,
                           size_t alen, const void *aad,
                           size_t len, const void *in, void *out,
                           size_t tlen, void *T);
typedef void *(*ADecFunc_t)(void *restrict x,
                            const void *restrict iv,
                            size_t alen, const void *aad,
                            size_t len, const void *in, void *out,
                            size_t tlen, const void *T);

// Because `obj' can be an identifier naming a macro
// as well as a pointer to a function , we have to
// make sure that `obj' is not parenthesized so that
// macro expansion won't be suppressed.

#define OUT_BYTES(obj)      ((unsigned)(obj(outBytes)))
#define BLOCK_BYTES(obj)    ((unsigned)(obj(blockBytes)))
#define KEY_BYTES(obj)      ((unsigned)(obj(keyBytes)))
#define KSCHD_BYTES(obj)    ((unsigned)(obj(keyschedBytes)))
#define CTX_BYTES(obj)      ((unsigned)(obj(contextBytes)))
#define IV_BYTES(obj)       ((unsigned)(obj(ivBytes)))
#define TAG_BYTES(obj)      ((unsigned)(obj(tagBytes)))

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

#endif /* MySuiteA_mysuitea_common_h */
