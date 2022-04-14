/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#ifndef MySuiteA_mysuitea_common_h
#define MySuiteA_mysuitea_common_h 1

#define static_assert _Static_assert

#include <limits.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
        tCryptoObj_t template; // otherwise.
    };
    union {
        const CryptoParam_t *param;
        IntPtr aux;
    };
};

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

    // Block Cipher Interfaces //
    EncFunc = 21, DecFunc = 22, KschdFunc = 23,

    // Permutation Interfaces //
    PermuteFunc = 24,

    // Keyed Context Initialization Function (AEAD, HMAC, etc.) //
    // 2021-03-20 addition for ``KInitFunc'':
    // applicable to both instances and parameterized instance templates.
    KInitFunc = 25,

    // Hash & XOF Functions //
    // 2021-03-20 addition for ``InitFunc'':
    // applicable to both instances and parameterized instance templates.
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

    // Obtains a set of parameter presets.
    PKParamsFunc = 121,

    PKKeygenFunc = 122,
    PKEncFunc = 123, PKDecFunc = 124, // Key Encapsulation Mechanism
    PKSignFunc = 125, PKVerifyFunc = 126, // Digital Signature Schemes

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
typedef void (*AEncFunc_t)(void *restrict x,
                           void const *iv,
                           size_t alen, void const *aad,
                           size_t len, void const *in, void *out,
                           size_t tlen, void *T);
// returns ``out'' on success and ``NULL'' on decryption failure.
typedef void *(*ADecFunc_t)(void *restrict x,
                            void const *iv,
                            size_t alen, void const *aad,
                            size_t len, void const *in, void *out,
                            size_t tlen, void const *T);

// Alias additions for PRNG/DRBG.
typedef KInitFunc_t     InstInitFunc_t;
typedef PKInitFunc_t    PInstInitFunc_t;
typedef WriteFunc_t     ReseedFunc_t;
typedef ReadFunc_t      GenFunc_t;

// ``index'' starts at 0,
// at which the function returns the length of parameter vector.
//
// For ``index'' greater than 0,
// The function sets ``out'' to a certain parameter set
// and returns the expected security level in bits.
//
// The function returns 0 to indicate end of list.
//
typedef int (*PKParamsFunc_t)(int index, CryptoParam_t *out);

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

#define OUT_BYTES(obj)      ((IntPtr)(obj(outBytes)))
#define BLOCK_BYTES(obj)    ((IntPtr)(obj(blockBytes)))
#define KEY_BYTES(obj)      ((IntPtr)(obj(keyBytes)))
#define KSCHD_BYTES(obj)    ((IntPtr)(obj(keyschedBytes)))
#define CTX_BYTES(obj)      ((IntPtr)(obj(contextBytes)))
#define IV_BYTES(obj)       ((IntPtr)(obj(ivBytes)))
#define TAG_BYTES(obj)      ((IntPtr)(obj(tagBytes)))

// In case C doesn't expand nested macro.
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
