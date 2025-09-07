/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#ifndef MySuiteA_mysuitea_common_h
#define MySuiteA_mysuitea_common_h 1

#include <limits.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define static_assert _Static_assert

#if true
// 2022-05-23:
// This one hosted header is added so that
// codes may pass the check in the linter.
// Can be changed to false if desired.
#include <assert.h>
#else
#define assert(...) ((void)0)
#endif

static_assert(CHAR_BIT == 8, "MySuiteA supports only octet-oriented targets!");
static_assert(sizeof(int) == 4, "Adaptation needed unless int's 32-bit!");
static_assert(sizeof(void *) >= 4, "Short pointers are untested!");

#ifdef ENABLE_HOSTED_HEADERS
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif /* ENABLE_HOSTED_HEADERS */

#define xglue(a,b) a##b
#define glue(a,b) xglue(a,b)

// <s>2020-11-21</s>:
// Per https://stackoverflow.com/q/64894785
// ``uintptr_t'' is changed to ``uintmax_t'', and the
// following static assertion is added.
///
// 2020-12-24:
// ``uintmax_t'' is, on my second thought, an overkill.
//
// What I really need, is a type to represent the byte addresses and ranges
// of the working memory space. Under mainstream memory models such as
// ILP32 and LP64, ``size_t'', ``uintptr_t'' would both work for me; and
// even with unconventional memory models, where function and objects
// doesn't share address space, it's exceptionally rare for code to exceed
// sizes as big as 2^32 bytes. (It's so much so that x86-64 and its ABI
// don't extend the "immediate" operand for CALL instruction to 64-bits for
// relatively positioned codes.)
///
// 2021-03-09:
// The name of the type is changed to the more "semantic" ``IntPtr'',
// allowing its name to be more meaningful and can be re-defined when
// need arises. It is intentional that the type is signed.

// Users of this library may change this type definition
// should their memory model require special treatment.
typedef intptr_t IntPtr;

static_assert(
    sizeof(IntPtr) == sizeof(size_t) &&
    sizeof(IntPtr) == sizeof(void (*)(void)),
    "Expectation on the compilation environment didn't hold!");

// 2021-09-04:
// Notes had been migrated to documentation.
// See "doc/api.html" for a description of
// MySuiteA's uniform algorithm interface.

typedef struct CryptoParam CryptoParam_t;

typedef IntPtr (*iCryptoObj_t)(int q);
typedef IntPtr (*tCryptoObj_t)(const CryptoParam_t *P, int q);

struct CryptoParam {
    union {
        iCryptoObj_t info; // if param/aux is NULL,
        tCryptoObj_t template; // otherwise (this field is obsolescent).
        tCryptoObj_t factory; // `template` is a keyword in C++.
    };
    union {
        const CryptoParam_t *param;
        IntPtr aux;
    };
};

// 2024-08-24:
//
// This macro was called ``ECDH_HASH_NULL'', and was for use
// in *_SIZE and *_INIT macros indicating that the elliptic-curve
// working context was an ``ECC_Base_Ctx_Hdr_t'' rather than
// an ``ECC_Hash_Ctx_Hdr_t'' in ecc-common.
//
// Now that ML-DSA need a way to specify the use and non-use of
// pre-hashing, a ``NULL'' hashing algorithm crypto object is
// needed. Futher considering there may be other places needing
// a way to specify a crypto object that's not used, a generic
// "Null" crypto object is defined for this purpose.
//
#define CRYPTO_OBJ_NULL(q) (0)
IntPtr iCryptoObj_Null(int q);

typedef struct {
    // [2023-08-09-SepParams]:
    // ----------
    //
    // In making PKC object codes in MySuiteA independent of instantiation
    // parameters, some issues were raised:
    //
    // While it's not an anti-pattern to use functions to retrieve parameters
    // for an algorithm instance (see:
    // https://softwareengineering.stackexchange.com/q/446914), a feature
    // originally planned could not be executed - It was impossible to specify
    // an algorithm family as parameter and let the function choose appropriate
    // parameter based on the description.
    //
    // Several ideas came up: specify the paradigm of the algorithm, specify
    // the SDO and Number of the standard, etc. It was impossible in particular
    // to distinguish SHA-3 hash functions and the 2 SHAKE XOF instances.
    //
    // A goal, nonetheless must be achieved, is to let the user of this library
    // to obtain usable PKC algorithm instance, in a way agnostic to the
    // requirement of the parameters as expected by the algorithm.
    //
    int secbits;
    tCryptoObj_t algo;
    CryptoParam_t *param;
} PKC_Algo_Inst_t;

typedef struct {
    union {
        size_t  len;
        IntPtr  info;
    };
    union {
        void const  *dat;
        void        *buf;
    };
} bufvec_t;

// Native CPU Instruction Implementation of Algorithms.
// The following flags determines the compile-time behavior
// of code definition.
//
// The additional ``NI_<ALGO>'' determines algorithm-specific
// behavior at compile time.
//
// If ``NI_<ALGO>'' is 'NI_RUNTIME', then ``ni_<algo>_conf'' will
// be the boolean value that determines whether the next query
// to the crypto-object returns the optimized implementation
// (if true), or the reference implementation (if false).
//
// ``ni_<algo>_conf'' are objects of type ``int'' with external
// linkage, multi-threaded codes must use additional synchronization
// to protect access to them. Their default value is 'false'.
#define NI_NEVER    0
#define NI_ALWAYS   1
#define NI_RUNTIME  2

enum {
    //-- Symmetric-Key Cryptography --//
    // 1-19: compile-time queries,
    // 21-39: link-time queries,
    // 41-59: additional compile-time queries.
    // 61-79: additional link-time queries.
    // 81-89: rare-use compile-time queries.
    // 91-99: rare-use link-time queries.

    // Applicable to
    // 1.) Primitives whose output length are fixed and constant.
    //
    // - For hash functions, this is the length of the digest in bytes.
    // - [2022-04-14]: For random oracles that supports domain separation
    //   for fixed-length and arbitrary-length output, the value of
    //   this query is -1.
    //
    outBytes = 1,

    // Applicable to
    // 1.) Fixed-length keyed or unkeyed permutations.
    // 2.) Iterated bufferred processing primitives.
    //
    blockBytes = 2,

    // Applicable to
    // 1.) All keyed primitives.
    //
    // - If positive, the primitive accepts only keys of fixed length;
    // - if negative, the primitive accepts keys of length up to
    //   the absolute value of this parameter;
    // - values with absolute values smaller than or equal to 4 have
    //   special meanings;
    // - a value of -1 specifies that the key may be of unlimited length;
    keyBytes = 3,

    // Applicable to
    // 1.) All iterated keyed permutation with at least 1 iteration.
    //
    keyschedBytes = 4,

    // Applicable to
    // 1.) Primitives reusing working variables for invocations.
    // 2.) Primitives saving working varibles for later resumption.
    //
    contextBytes = 5,

    // Applicable to
    // 1.) AEAD.
    //
    ivBytes = 6, tagBytes = 7,

    // Added 2022-08-29:
    // For parallel and tree hashing algorithms, there's the chunk size
    // parameter. Each chunk is processed single-threaded, multiple chunks
    // may be processed in parallel.
    //
    chunkBytes = 8,

    // Added 2023-08-07:
    // Most PKC algorithm expect hash function of fixed output length.
    // This query parameter fits that need when a XOF is provided.
    outTruncBytes = 9,
    
    // Block Cipher Interfaces //
    EncFunc = 21, DecFunc = 22, KschdFunc = 23,

    // Permutation Interfaces //
    PermuteFunc = 24,

    // Keyed Context Initialization Function (AEAD, HMAC, etc.) //
    // 2021-03-20 addition for ``KInitFunc'':
    // applicable to both instances and parameterized instance factories.
    KInitFunc = 25,

    // Hash & XOF Functions //
    // 2021-03-20 addition for ``InitFunc'':
    // applicable to both instances and parameterized instance factories.
    //
    // - [2022-04-14]: For random oracles that supports domain separation
    //   for fixed-length and arbitrary-length output, the FinalFunc
    //   provides for fixed-length output, whereas the XofFinalFunc and
    //   ReadFunc provides for arbitrary-length output.
    //
    InitFunc = 26,
    UpdateFunc = 27, WriteFunc=UpdateFunc,
    FinalFunc = 28, XofFinalFunc = 29,
    ReadFunc = 30,

    // AEAD Functions //
    AEncFunc = 31, ADecFunc = 32,

    // Parallel and Tree Hashing Functions (Added 2022-09-04) //
    //
    // The update and finalization functions of parallel and tree
    // hashing functions take an additional "threads crew" object
    // to exploit the parallelism of the host platform. This poses
    // new requirements on designing APIs for them in an elegant way.
    //
    // The current idea is that, apart from the initialization function
    // that is in common with regular hashing algorithms, parallel and
    // tree hashing algorithms will have 3 functions of their own to
    // perform input updating, final calculation, and reading output.
    // The update and finalization functions will take an additional
    // "threads crew" object as argument for exploiting the parallelism
    // available on the platform; the read function will behave similar
    // to that of XOF's (because parallel and tree hashing algorithms are
    // predominantly XOFs) read, except that it takes an additional flags
    // argument to customize its behavior. These new APIs will contain
    // a number in their name to indicate the number of arguments they
    // take. Similar convention exists in Unix APIs (e.g. "accept4",
    // "dup3", "pipe2", etc.).
    Update4Func = 33, Final2Func = 34, Read4Func = 35,

    //-- Public-Key Cryptography --//
    // 101-119: compile-time queries.
    // 121-139: link-time algorithmic subroutines' queries.
    // 141-160: link-time format encoding subroutines' queries.

    bytesCtxPriv = 101, bytesCtxPub = 102,

    // e.g.
    // ECC has keys whose sizes are determined by the domain parameters
    // of the curve; whereas RSA has parameters determined by the size
    // of the modulus and the number of prime factors.
    //
    // The significance of this is that, when loading keys, the size of
    // the working context is determined by the key decoder if this is 1,
    // and by the compile-time or run-time parameters if this is 0.
    //
    // The size of the working context for key generation is independent of
    // this and can be determined by either compile-time and run-time
    // parameter, or the key generating function.
    isParamDetermByKey = 103,

    // Added 2023-11-16:
    // Some DSS needs a nonce during signing. This and the following queries
    // describe caracteristics of implementation of nonce generation.
    dssNonceNeeded = 104,

    // Added 2023-11-16:
    // It is increasingly the case where DSS incorporate deterministic signing
    // as part of signing algorithm, to avoid defects from RNGs; additionally,
    // to avoid fault side-channels, additional entropy are incorporated as
    // part of the deterministic nonce generation. However, when existing
    // algorithm cannot achieve such capability without incorporating external
    // codes for PRNG implementations, agility is favoured to allow maximum
    // possibility of freedom of combination; in which case, an additional
    // "signing driver" function is provided, with this query returning true.
    dssExternRngNeededForNonce = 105,

    // Added 2024-10-05:
    // Determines the characteristics of pre-hashing support of the algorithm
    // instance ITSELF - although an algorithm may support a variety of
    // message hashing, reporting it for different instance across all
    // algorithm instances is neither useful from usage point of view,
    // nor viable from implementation point of view.
    dssPreHashingType = 106,

    // Obtains a set of parameter presets.
    //
    // [2023-08-09-SepParams]:
    // It has been noted, that the implementation of this function required
    // PKC code objects to include references to interfaces of algorithms'
    // parameters. For the benefit of allowing PKC codes to combine more
    // freely with the parameters users may choose, this query is obsoleted.
    //
    //- PKParamsFunc = 121,

    PKKeygenFunc = 122,
    PKEncFunc = 123, PKDecFunc = 124, // Key Encapsulation Mechanism
    PKSignFunc = 125, PKVerifyFunc = 126, // Digital Signature Schemes
    PKIncSignInitFunc = 127, PKIncSignFinalFunc = 128, // Pre-Hash DSS
    PKIncVerifyInitFunc = 129, PKIncVerifyFinalFunc = 130, // Pre-Hash DSS

    // Key Material Saving and Loading //
    // - Encoder and Decoder work on the working contexts of their
    //   respective key types.
    // - Public key exporter exports public key from a private-key context
    //   which contains the keypair generated from the keygen function
    //   or imported using a private key decoding function.
    // - While public key exporter is sufficient for importing public key
    //   generated elsewhere, dedicated encoder for the public-key context
    //   allows for transcoding between different public-key formats
    //   (e.g. DER, CBOR, JSON, etc.) as had been possible with private keys.
    PKPrivkeyEncoder = 141, PKPubkeyEncoder = 142, PKPubkeyExporter = 143,
    PKPrivkeyDecoder = 144, PKPubkeyDecoder = 145,

    // Ciphergram Saving and Loading //
    PKCtEncoder = 146, // Ct: Cipher Transcript which can include
    PKCtDecoder = 147, //     both ciphertexts and signatures.

    // 2022-03-17 Additions: Miscellaneous //
    XctrlFunc = 201, // algorithm-specific working context control function.
    PubXctrlFunc = 202, // for public-key working contexts.
    PrivXctrlFunc = 203, // for private-key working contexts.

    // Information macros evaluates to 0
    // for queries not applicable to them.

    //-- Private-Use Range --//
    qPrivateUseBegin = 20000, // above 2**14
    qPrivateUseEnd = 29999, // below 2**15
};

// Aliases additions for PRNG/DRBG.
enum {
    seedBytes     = keyBytes,
    InstInitFunc  = KInitFunc,
    ReseedFunc    = WriteFunc,
    GenFunc       = ReadFunc,
};

// Added 2024-10-05.
enum {
    // This algorithm does not support pre-hashing at all.
    dssPreHashing_Unsupported = 0,

    // Pre-hashing offered in an interface, and the algorithm behaves
    // the same as if the message is buffered and signed all-at-once
    dssPreHashing_Interface = 1,

    // Pre-hashing offered in an interface, but algorithm will behave
    // differently from that of buffering and signing all-at-once.
    dssPreHashing_Variant = 2,

    // Pre-hashing is supported in a separate algorithm instance.
    dssPreHashing_ParamSet = 3,
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

// Same note as that for ``KInitFunc_t''.
typedef void *(*PKInitFunc_t)(const CryptoParam_t *P,
                             void *restrict x,
                             void const *restrict k,
                             size_t klen);
typedef void (*PInitFunc_t)(const CryptoParam_t *P, void *restrict x);

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
typedef void *(*AEncFunc_t)(void *restrict x,
                            size_t ivlen, void const *iv,
                            size_t alen, void const *aad,
                            size_t len, void const *in, void *out,
                            size_t tlen, void *T);
// returns ``out'' on success and ``NULL'' on decryption failure.
typedef void *(*ADecFunc_t)(void *restrict x,
                            size_t ivlen, void const *iv,
                            size_t alen, void const *aad,
                            size_t len, void const *in, void *out,
                            size_t tlen, void const *T);

// Alias additions for PRNG/DRBG.
typedef KInitFunc_t     InstInitFunc_t;
typedef PKInitFunc_t    PInstInitFunc_t;
typedef WriteFunc_t     ReseedFunc_t;
typedef ReadFunc_t      GenFunc_t;

// 2022-09-04, parallel and tree hashing additions.

#include "1-oslib/TCrew-common.h"

typedef void (*Update4Func_t)(void *restrict x,
                              void const *restrict data,
                              size_t len,
                              TCrew_Abstract_t *restrict tc);

typedef void (*Final2Func_t)(void *restrict x,
                             TCrew_Abstract_t *restrict tc);

#define HASHING_READ4_REWIND 1

typedef void (*Read4Func_t)(void *restrict x,
                            void *restrict data,
                            size_t len, int flags);

// [2023-08-09-SepParams]: This type is obsoleted.
//
// ``index'' starts at 0,
// at which the function returns the length of parameter vector.
//
// For ``index'' greater than 0,
// The function sets ``out'' to a certain parameter set
// and returns the expected security level in bits.
//
// The function returns 0 to indicate end of list.
//
//- typedef int (*PKParamsFunc_t)(int index, CryptoParam_t *out);

typedef IntPtr (*PKKeygenFunc_t)(void *restrict x,
                                 CryptoParam_t *restrict param,
                                 GenFunc_t prng_gen, void *restrict prng);

// returns ss on success and NULL on failure.
// by convention, if ss is NULL, *sslen is set to its length.
typedef void *(*PKEncFunc_t)(void *restrict x,
                             void *restrict ss, size_t *restrict sslen,
                             GenFunc_t prng_gen, void *restrict prng);

// returns x on success and NULL on failure.
// if ss is NULL, *sslen is set to its length.
typedef void *(*PKDecFunc_t)(void *restrict x,
                            void *restrict ss, size_t *restrict sslen);

// returns x on success and NULL on failure.
typedef void *(*PKSignFunc_t)(void *restrict x,
                              void const *restrict msg, size_t msglen,
                              GenFunc_t prng_gen, void *restrict prng);

// returns msg on success and NULL on failure.
typedef void const *(*PKVerifyFunc_t)(void *restrict x,
                                      void const *restrict msg,
                                      size_t msglen);

// returns a incremental signing/verifying context; the pointer to its update
// function is written to ``placeback''; the corresponding
// ``PKIncSignFinalFunc_t'' or ``PKIncVerifyFinalFunc_t'' finalizes it.
typedef void *(*PKIncSignInitFunc_t)(void *restrict x,
                                     UpdateFunc_t *placeback);

typedef PKIncSignInitFunc_t PKIncVerifyInitFunc_t;

// finalizes the incremental signing context and produce a signature.
typedef void *(*PKIncSignFinalFunc_t)(void *restrict x,
                                      GenFunc_t prng_gen,
                                      void *restrict prng);

// finalizes the incremental verification context and evaluate the predicate.
// ``x'' if verification passes, and NULL otherwise.
typedef void *(*PKIncVerifyFinalFunc_t)(void *restrict x);

// 2-pass codecs similar to that in "2-asn1/der-codec.h".
typedef IntPtr (*PKKeyEncoder_t)(void const *restrict any,
                                 void *restrict enc,
                                 size_t enclen,
                                 CryptoParam_t *restrict aux);

// Same as above.
typedef IntPtr (*PKKeyDecoder_t)(void *restrict any,
                                 void const *restrict enc,
                                 size_t enclen,
                                 CryptoParam_t *restrict aux);

// returnx c on success and NULL on failure.
// if c is NULL, *len is set to its length.
typedef void *(*PKCiphergramEncoder_t)(void *restrict x,
                                       void *restrict c, size_t *len);

// returns x on success and NULL on failure.
typedef void *(*PKCiphergramDecoder_t)(void *restrict x,
                                       void const *restrict c, size_t len);

// 2022-03-17 Additions: 1 function prototype.
typedef void *(*XctrlFunc_t)(void *restrict x,
                             int cmd,
                             const bufvec_t *restrict bufvec,
                             int veclen,
                             int flags);

// Because `obj' can be an identifier naming a macro
// as well as a pointer to a function , we have to
// make sure that `obj' is not parenthesized so that
// macro expansion won't be suppressed.

#define OUT_NOMINAL(obj)    ((IntPtr)(obj(outBytes)))
#define BLOCK_BYTES(obj)    ((IntPtr)(obj(blockBytes)))
#define KEY_BYTES(obj)      ((IntPtr)(obj(keyBytes)))
#define KSCHD_BYTES(obj)    ((IntPtr)(obj(keyschedBytes)))
#define CTX_BYTES(obj)      ((IntPtr)(obj(contextBytes)))
#define IV_BYTES(obj)       ((IntPtr)(obj(ivBytes)))
#define TAG_BYTES(obj)      ((IntPtr)(obj(tagBytes)))
#define CHUNK_BYTES(obj)    ((IntPtr)(obj(chunkBytes)))
#define OTRUNC_BYTES(obj)   ((IntPtr)(obj(outTruncBytes)))

// Helper macro
#define OUT_BYTES(obj)                                                  \
    (OUT_NOMINAL(obj) > 4 ? OUT_NOMINAL(obj) : OTRUNC_BYTES(obj))

// In case C doesn't expand nested macro.
#define BLOCK_BYTES_1(obj)  ((IntPtr)(obj(blockBytes)))
#define BLOCK_BYTES_2(obj)  ((IntPtr)(obj(blockBytes)))
#define BLOCK_BYTES_3(obj)  ((IntPtr)(obj(blockBytes)))
#define CTX_BYTES_1(obj)    ((IntPtr)(obj(contextBytes)))
#define CTX_BYTES_2(obj)    ((IntPtr)(obj(contextBytes)))
#define CTX_BYTES_3(obj)    ((IntPtr)(obj(contextBytes)))

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

#define UPDATE4_FUNC(obj)   ((Update4Func_t)(obj(Update4Func)))
#define FINAL2_FUNC(obj)    ((Final2Func_t)(obj(Final2Func)))
#define READ4_FUNC(obj)     ((Read4Func_t)(obj(Read4Func)))

#define XCTRL_FUNC(obj)         ((XctrlFunc_t)(obj(XctrlFunc)))
#define PUB_XCTRL_FUNC(obj)     ((XctrlFunc_t)(obj(PubXctrlFunc)))
#define PRIV_XCTRL_FUNC(obj)    ((XctrlFunc_t)(obj(PrivXctrlFunc)))

// Aliases additions for PRNG/DRBG.
#define SEED_BYTES(obj)     ((IntPtr)(obj(seedBytes)))
#define INST_INIT_FUNC(obj) ((InstInitFunc_t)(obj(InstInitFunc)))
#define RESEED_FUNC(obj)    ((ReseedFunc_t)(obj(ReseedFunc)))
#define GEN_FUNC(obj)       ((GenFunc_t)(obj(GenFunc)))

#define ERASE_STATES(buf, len)                          \
    do {                                                \
        char volatile *ba = (void volatile *)(buf);     \
        size_t l = (size_t)(len), i;                    \
        for(i=0; i<l; i++) ba[i] = 0;                   \
    } while(false)

#endif /* MySuiteA_mysuitea_common_h */
