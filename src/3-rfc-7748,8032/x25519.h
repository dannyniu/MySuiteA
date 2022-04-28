/* DannyNiu/NJF, 2022-04-27. Public Domain. */

#ifndef MySuiteA_x25519_h
#define MySuiteA_x25519_h 1

#define XECDH X25519

#include "xecdh.h.h"

#define xX25519_KeyCodec(q) (                                           \
        q==PKKeygenFunc ? (IntPtr)X25519_Keygen :                       \
        q==PKPrivkeyEncoder ? (IntPtr)X25519_Encode_PrivateKey :        \
        q==PKPrivkeyDecoder ? (IntPtr)X25519_Decode_PrivateKey :        \
        q==PKPubkeyExporter ? (IntPtr)X25519_Encode_PublicKey :         \
        q==PKPubkeyEncoder ? (IntPtr)X25519_Encode_PublicKey :          \
        q==PKPubkeyDecoder ? (IntPtr)X25519_Decode_PublicKey :          \
        0)

#define cX25519(q) (                            \
        q==bytesCtxPriv ? XECDH_CTX_SIZE(255) : \
        q==bytesCtxPub ? XECDH_CTX_SIZE(255) :  \
        q==isParamDetermByKey ? false :         \
        0)

#define xX25519(q) (                                    \
        q==PKParamsFunc ? (IntPtr)X25519_PKParams :     \
        q==PKKeygenFunc ? (IntPtr)X25519_Keygen :       \
        q==PKEncFunc ? (IntPtr)X25519_Enc :             \
        q==PKDecFunc ? (IntPtr)X25519_Dec :             \
        cX25519(q) )

#define xX25519_CtCodec(q) (                                    \
        q==PKEncFunc ? (IntPtr)X25519_Enc :                     \
        q==PKDecFunc ? (IntPtr)X25519_Dec :                     \
        q==PKCtEncoder ? (IntPtr)X25519_Encode_Ciphertext :     \
        q==PKCtDecoder ? (IntPtr)X25519_Decode_Ciphertext :     \
        0)

IntPtr iX25519_KeyCodec(int q);
IntPtr tX25519(const CryptoParam_t *P, int q);
IntPtr iX25519_CtCodec(int q);

#undef XECDH

#endif /* MySuiteA_x25519_h */
