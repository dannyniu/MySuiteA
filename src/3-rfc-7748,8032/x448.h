/* DannyNiu/NJF, 2022-04-28. Public Domain. */

#ifndef MySuiteA_x448_h
#define MySuiteA_x448_h 1

#define XECDH X448

#include "xecdh.h.h"

#define xX448_KeyCodec(q) (                                     \
        q==PKKeygenFunc ? (IntPtr)X448_Keygen :                 \
        q==PKPrivkeyEncoder ? (IntPtr)X448_Encode_PrivateKey :  \
        q==PKPrivkeyDecoder ? (IntPtr)X448_Decode_PrivateKey :  \
        q==PKPubkeyExporter ? (IntPtr)X448_Encode_PublicKey :   \
        q==PKPubkeyEncoder ? (IntPtr)X448_Encode_PublicKey :    \
        q==PKPubkeyDecoder ? (IntPtr)X448_Decode_PublicKey :    \
        0)

#define cX448(q) (                              \
        q==bytesCtxPriv ? XECDH_CTX_SIZE(448) : \
        q==bytesCtxPub ? XECDH_CTX_SIZE(448) :  \
        q==isParamDetermByKey ? false :         \
        0)

#define xX448(q) (                                      \
        q==PKParamsFunc ? (IntPtr)X448_PKParams :       \
        q==PKKeygenFunc ? (IntPtr)X448_Keygen :         \
        q==PKEncFunc ? (IntPtr)X448_Enc :               \
        q==PKDecFunc ? (IntPtr)X448_Dec :               \
        cX448(q) )

#define xX448_CtCodec(q) (                                      \
        q==PKEncFunc ? (IntPtr)X448_Enc :                       \
        q==PKDecFunc ? (IntPtr)X448_Dec :                       \
        q==PKCtEncoder ? (IntPtr)X448_Encode_Ciphertext :       \
        q==PKCtDecoder ? (IntPtr)X448_Decode_Ciphertext :       \
        0)

IntPtr iX448_KeyCodec(int q);
IntPtr tX448(const CryptoParam_t *P, int q);
IntPtr iX448_CtCodec(int q);

#undef XECDH

#endif /* MySuiteA_x448_h */
