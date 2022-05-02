/* DannyNiu/NJF, 2022-04-27. Public Domain. */

#ifndef MySuiteA_rfc_7748_h
#define MySuiteA_rfc_7748_h 1

// 2022-05-02:
//
// In the first round of implementing X25519 and X448, there were 2 separate
// algorithm construction crypto-objects for the 2 instances, both taking
// no parameter. A problem with this setup is that, if memory allocation
// functions return NULL as instantiation parameter, and subsequently the
// crypto-object and the parameter are wrapped in a 'container' crypto-param
// structure, the recipiant of this structure will misuse the algorithm
// construction crypto-object as an instance crypto-object and provide
// invalid arguments.
//
// The solution to be implemented to solve this problem is to 'generalize'
// the XECDH functions to make them take a Montgomery curve as parameter.

#include "../2-ec/ecMt.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4 * 5 | 4 * 6 | 8 * 4
typedef struct {
    uint32_t offset_k, offset_K; // private and public key.
    uint32_t offset_P; // public key from the peer.
    uint32_t offset_opctx;
    IntPtr status;
    ecMt_curve_t const *curve;
} XECDH_Ctx_Hdr_t;

typedef CryptoParam_t XECDH_Param_t[1];

IntPtr XECDH_Keygen(
    XECDH_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

IntPtr XECDH_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr XECDH_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

#define XECDH_Export_PublicKey XECDH_Encode_PublicKey

IntPtr XECDH_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr XECDH_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

void *XECDH_Enc(
    XECDH_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng);

void *XECDH_Dec(
    XECDH_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen);

void *XECDH_Encode_Ciphertext(
    XECDH_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t *ctlen);

void *XECDH_Decode_Ciphertext(
    XECDH_Ctx_Hdr_t *restrict x,
    void const *restrict ct, size_t ctlen);

int XECDH_PKParams(int index, CryptoParam_t *out);

#define XECDH_CTX_SIZE(ecMt) (                          \
        sizeof(XECDH_Ctx_Hdr_t) +                       \
        ECMT_OPCTX_SIZE(ecMt(ecMt_BitsModulus)) +       \
        VLONG_BITS_SIZE(ecMt(ecMt_BitsModulus)) * 3     \
        )

#define XECDH_CTX_HDR_INIT(ecMt)                        \
    ((XECDH_Ctx_Hdr_t){                                 \
        .offset_opctx = sizeof(XECDH_Ctx_Hdr_t),        \
        .offset_k = sizeof(XECDH_Ctx_Hdr_t) +           \
        ECMT_OPCTX_SIZE(ecMt(ecMt_BitsModulus)) +       \
        VLONG_BITS_SIZE(ecMt(ecMt_BitsModulus)) * 0,    \
        .offset_K = sizeof(XECDH_Ctx_Hdr_t) +           \
        ECMT_OPCTX_SIZE(ecMt(ecMt_BitsModulus)) +       \
        VLONG_BITS_SIZE(ecMt(ecMt_BitsModulus)) * 1,    \
        .offset_P = sizeof(XECDH_Ctx_Hdr_t) +           \
        ECMT_OPCTX_SIZE(ecMt(ecMt_BitsModulus)) +       \
        VLONG_BITS_SIZE(ecMt(ecMt_BitsModulus)) * 2,    \
        .status = 0,                                    \
        .curve = (const void *)ecMt(ecMt_PtrCurveDef),  \
    })

#define XECDH_CTX_T(...)\
    union {                                             \
        XECDH_Ctx_Hdr_t header;                         \
        uint8_t blob[XECDH_CTX_SIZE(__VA_ARGS__)];      \
    }

#define xXECDH_KeyCodec(q) (                                    \
        q==PKKeygenFunc ? (IntPtr)XECDH_Keygen :                \
        q==PKPrivkeyEncoder ? (IntPtr)XECDH_Encode_PrivateKey : \
        q==PKPrivkeyDecoder ? (IntPtr)XECDH_Decode_PrivateKey : \
        q==PKPubkeyExporter ? (IntPtr)XECDH_Encode_PublicKey :  \
        q==PKPubkeyEncoder ? (IntPtr)XECDH_Encode_PublicKey :   \
        q==PKPubkeyDecoder ? (IntPtr)XECDH_Decode_PublicKey :   \
        0)

#define cXECDH(bits,q) (                                \
        q==bytesCtxPriv ? XECDH_CTX_SIZE(bits) :        \
        q==bytesCtxPub ? XECDH_CTX_SIZE(bits) :         \
        q==isParamDetermByKey ? false :                 \
        0)

#define xXECDH(bits,q) (                                \
        q==PKParamsFunc ? (IntPtr)XECDH_PKParams :      \
        q==PKKeygenFunc ? (IntPtr)XECDH_Keygen :        \
        q==PKEncFunc ? (IntPtr)XECDH_Enc :              \
        q==PKDecFunc ? (IntPtr)XECDH_Dec :              \
        cXECDH(bits,q) )

#define xXECDH_CtCodec(q) (                                     \
        q==PKEncFunc ? (IntPtr)XECDH_Enc :                      \
        q==PKDecFunc ? (IntPtr)XECDH_Dec :                      \
        q==PKCtEncoder ? (IntPtr)XECDH_Encode_Ciphertext :      \
        q==PKCtDecoder ? (IntPtr)XECDH_Decode_Ciphertext :      \
        0)

IntPtr iXECDH_KeyCodec(int q);
IntPtr tXECDH(const CryptoParam_t *P, int q);
IntPtr iXECDH_CtCodec(int q);

#endif /* MySuiteA_rfc_7748_h */
