/* DannyNiu/NJF, 2023-09-21. Public Domain. */

#ifndef MySuiteA_MLDSA_h
#define MySuiteA_MLDSA_h 1

// 2023-10-04:
// The draft FIPS-204-IPD contains a logical error in the
// ExpandMask subroutine making the currently specified
// scheme sub-optimal. Although this doesn't technically
// hamper interoperability, it makes it essentially
// impossible to have test vectors to verify the correctness
// of implementations. Therefore, the MySuiteA implementation
// of ML-DSA (a.k.a. Dilithium) is currently experimental.

#include "../2-pq-crystals/dilithium-aux.h"
#include "../2-hash/hash-funcs-set.h"

// [0] and [1] are k and l respectively.
// [2] is the hashing algorithm in pre-hash variants,
// null crypto object for pure variants.
typedef CryptoParam_t MLDSA_Param_t[3];

// data model:  SIP16  |  ILP32  |  LP64
// ----------+---------+---------+--------
// align spec: 4*(l+2) | 4*(l+4) | 4*(l+8)
// ---------------------------------------
// note: l = 64 + 32 + 14 + 16 + 256
typedef struct {
    uint8_t ctxstr[256];

    // seeds.
    uint8_t rho[32];
    uint8_t K[32];
    uint8_t tr[64];

    // hashing context.
    hash_funcs_set_t hfuncs;
    uint32_t offset_hashctx;
    uint32_t hashlen;
    int32_t hash_oid_tab_ind;

    int32_t status; // refer to "2-rsa/pkcs1-padding.h".

    // parameters.
    int32_t k, l;

    // key components.
    uint32_t offset_Ahat; // k x l
    uint32_t offset_s1hat; // l
    uint32_t offset_s2hat; // k
    uint32_t offset_t1, offset_t0hat; // k x2

    // signature variables.
    uint32_t offset_yz; // l
    uint32_t offset_w; // k
    uint32_t offset_cs; // k + l.

    // scratch registers.
    uint8_t challenge[64]; // also reused as mu.
    module256_t c;
} MLDSA_Priv_Ctx_Hdr_t;

#define MLDSA_PRIV_CTX_SIZE_X(k,l,hash) (               \
        sizeof(MLDSA_Priv_Ctx_Hdr_t) +                  \
        hash(contextBytes) +                            \
        sizeof(module256_t) * (k*l + k*5 + l*3) )

#define SIZEOF_MLDSA_PRIV_HDR(hash)                     \
    (sizeof(MLDSA_Priv_Ctx_Hdr_t) + hash(contextBytes))

#define OFFSET_FORMULA(expr,hash)                               \
    (SIZEOF_MLDSA_PRIV_HDR(hash) + SIZEOF_M256 * (expr))

#define MLDSA_PRIV_CTX_SIZE(...) MLDSA_PRIV_CTX_SIZE_X(__VA_ARGS__)

#define MLDSA_PRIV_CTX_INIT_X(kp,lp,hashp)                              \
    ((MLDSA_Priv_Ctx_Hdr_t){                                            \
        .k = kp, .l = lp,                                               \
        .hashlen = OUT_BYTES(hashp),                                    \
        .offset_hashctx = (                                             \
            CTX_BYTES(hashp) ?                                          \
            sizeof(MLDSA_Priv_Ctx_Hdr_t) : 0),                          \
        .hfuncs = HASH_FUNCS_SET_INIT(hashp),                           \
        .offset_Ahat  = OFFSET_FORMULA(0, hashp),                       \
        .offset_s1hat = OFFSET_FORMULA(kp*lp + kp*0 + lp*0, hashp),     \
        .offset_s2hat = OFFSET_FORMULA(kp*lp + kp*0 + lp*1, hashp),     \
        .offset_t1    = OFFSET_FORMULA(kp*lp + kp*1 + lp*1, hashp),     \
        .offset_t0hat = OFFSET_FORMULA(kp*lp + kp*2 + lp*1, hashp),     \
        .offset_yz    = OFFSET_FORMULA(kp*lp + kp*3 + lp*1, hashp),     \
        .offset_w     = OFFSET_FORMULA(kp*lp + kp*3 + lp*2, hashp),     \
        .offset_cs    = OFFSET_FORMULA(kp*lp + kp*4 + lp*2, hashp),     \
    })

#define MLDSA_PRIV_CTX_INIT(...) MLDSA_PRIV_CTX_INIT_X(__VA_ARGS__)

#define MLDSA_PRIV_CTX_T(...)                           \
    union {                                             \
        MLDSA_Priv_Ctx_Hdr_t header;                    \
        uint8_t blob[MLDSA_PRIV_CTX_SIZE(__VA_ARGS__)]; \
    }

// data model:  SIP16  |  ILP32  |  LP64
// ----------+---------+---------+--------
// align spec: 4*(l+2) | 4*(l+4) | 4*(l+8)
// ---------------------------------------
// note: l = 64 + 96 + 10 + 512
typedef struct {
    uint8_t ctxstr[256];

    uint8_t rho[32];
    uint8_t w1app[32*7]; // scratch register. 6 is sufficent, 7 is for padding.
    uint8_t tr[64];
    uint8_t c_hash[64]; // from a component of signature actually.

    // hashing context.
    hash_funcs_set_t hfuncs;
    uint32_t offset_hashctx;
    uint32_t hashlen;
    int32_t hash_oid_tab_ind;

    int32_t status; // refer to "2-rsa/pkcs1-padding.h".

    // parameters.
    int32_t k, l;

    // key components.
    uint32_t offset_Ahat; // k x l
    uint32_t offset_t1hat; // k

    // signature variables.
    uint32_t offset_z; // l
    uint32_t offset_h; // k

    // scratch registers.
    module256_t c, w;
} MLDSA_Pub_Ctx_Hdr_t;

#define MLDSA_PUB_CTX_SIZE_X(k,l,hash) (                \
        sizeof(MLDSA_Pub_Ctx_Hdr_t) +                   \
        hash(contextBytes) +                            \
        sizeof(module256_t) * (k*l + k*2 + l*1) )

#define SIZEOF_MLDSA_PUB_HDR(hash)                      \
    (sizeof(MLDSA_Pub_Ctx_Hdr_t) + hash(contextBytes))

#define OFFSET_EXPR(expr,hash)                          \
    SIZEOF_MLDSA_PUB_HDR(hash) + SIZEOF_M256 * (expr)

#define MLDSA_PUB_CTX_SIZE(...) MLDSA_PUB_CTX_SIZE_X(__VA_ARGS__)

#define MLDSA_PUB_CTX_INIT_X(kp,lp,hashp)                               \
    ((MLDSA_Pub_Ctx_Hdr_t){                                             \
        .k = kp, .l = lp,                                               \
        .hashlen = OUT_BYTES(hashp),                                    \
        .offset_hashctx = (                                             \
            CTX_BYTES(hashp) ?                                          \
            sizeof(MLDSA_Priv_Ctx_Hdr_t) : 0),                          \
        .hfuncs = HASH_FUNCS_SET_INIT(hashp),                           \
        .offset_Ahat  = OFFSET_EXPR(0, hashp),                          \
        .offset_t1hat = OFFSET_EXPR(kp*lp + kp*0 + lp*0, hashp),        \
        .offset_z     = OFFSET_EXPR(kp*lp + kp*1 + lp*0, hashp),        \
        .offset_h     = OFFSET_EXPR(kp*lp + kp*1 + lp*1, hashp),        \
    })

#define MLDSA_PUB_CTX_INIT(...) MLDSA_PUB_CTX_INIT_X(__VA_ARGS__)

#define MLDSA_PUB_CTX_T(...)                            \
    union {                                             \
        MLDSA_Pub_Ctx_Hdr_t header;                     \
        uint8_t blob[MLDSA_PUB_CTX_SIZE(__VA_ARGS__)];  \
    }

IntPtr MLDSA_Keygen(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

IntPtr MLDSA_Encode_PrivateKey(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

IntPtr MLDSA_Decode_PrivateKey(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

IntPtr MLDSA_Export_PublicKey(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

IntPtr MLDSA_Encode_PublicKey(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    void *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

IntPtr MLDSA_Decode_PublicKey(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict enc, size_t enclen,
    CryptoParam_t *restrict param);

void *MLDSA_Sign(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen,
    GenFunc_t prng_gen, void *restrict prng);

void const *MLDSA_Verify(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict msg, size_t msglen);

void *MLDSA_IncSign_Init(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback);

void *MLDSA_IncSign_Final(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    GenFunc_t prng_gen,
    void *restrict prng);

void *MLDSA_IncVerify_Init(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    UpdateFunc_t *placeback);

void *MLDSA_IncVerify_Final(
    MLDSA_Pub_Ctx_Hdr_t *restrict x);

void *MLDSA_Encode_Signature(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    void *restrict sig, size_t *siglen);

void *MLDSA_Decode_Signature(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    void const *restrict sig, size_t siglen);

void *MLDSA_Sign_Xctrl(
    MLDSA_Priv_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

void *MLDSA_Verify_Xctrl(
    MLDSA_Pub_Ctx_Hdr_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags);

enum {
    MLDSA_cmd_null      = 0,

    // ``bufvec[0].dat'' points to the context string data.
    // ``bufvec[0].len'' must be less than or equal to 255.
    MLDSA_set_ctxstr    = 1,
};

#define xMLDSA_KeyCodec(q) (                                    \
        q==PKKeygenFunc ? (IntPtr)MLDSA_Keygen :                \
        q==PKPrivkeyEncoder ? (IntPtr)MLDSA_Encode_PrivateKey : \
        q==PKPrivkeyDecoder ? (IntPtr)MLDSA_Decode_PrivateKey : \
        q==PKPubkeyExporter ? (IntPtr)MLDSA_Export_PublicKey :  \
        q==PKPubkeyEncoder ? (IntPtr)MLDSA_Encode_PublicKey :   \
        q==PKPubkeyDecoder ? (IntPtr)MLDSA_Decode_PublicKey :   \
        0)

#define cMLDSA(k,l,h,q) (                                       \
        q==bytesCtxPriv ? MLDSA_PRIV_CTX_SIZE(k,l,h) :          \
        q==bytesCtxPub ? MLDSA_PUB_CTX_SIZE(k,l,h) :            \
        q==isParamDetermByKey ? false :                         \
        q==dssPreHashingType ? dssPreHashing_Interface :        \
        0)

#define xMLDSA(k,l,h,q) (                                               \
        q==PKKeygenFunc ? (IntPtr)MLDSA_Keygen :                        \
        q==PKSignFunc ? (IntPtr)MLDSA_Sign :                            \
        q==PKVerifyFunc ? (IntPtr)MLDSA_Verify :                        \
        q==PKIncSignInitFunc ? (IntPtr)MLDSA_IncSign_Init :             \
        q==PKIncSignFinalFunc ? (IntPtr)MLDSA_IncSign_Final :           \
        q==PKIncVerifyInitFunc ? (IntPtr)MLDSA_IncVerify_Init :         \
        q==PKIncVerifyFinalFunc ? (IntPtr)MLDSA_IncVerify_Final :       \
        q==PubXctrlFunc ? (IntPtr)MLDSA_Verify_Xctrl :                  \
        q==PrivXctrlFunc ? (IntPtr)MLDSA_Sign_Xctrl :                   \
        cMLDSA(k,l,h,q) )

#define xMLDSA_CtCodec(q) (                                     \
        q==PKSignFunc ? (IntPtr)MLDSA_Sign :                    \
        q==PKVerifyFunc ? (IntPtr)MLDSA_Verify :                \
        q==PKCtEncoder ? (IntPtr)MLDSA_Encode_Signature :       \
        q==PKCtDecoder ? (IntPtr)MLDSA_Decode_Signature :       \
        0)

IntPtr iMLDSA_KeyCodec(int q);
IntPtr tMLDSA(const CryptoParam_t *P, int q);
IntPtr iMLDSA_CtCodec(int q);

#endif /* MySuiteA_MLDSA_h */
