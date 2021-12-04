/* DannyNiu/NJF, 2021-01-13. Public Domain. */

#ifndef MySuiteA_rsa_codec_der_h
#define MySuiteA_rsa_codec_der_h 1

#include "rsa.h"
#include "../2-asn1/der-codec.h"

IntPtr ber_tlv_encode_RSAPrivateKey(BER_TLV_ENCODING_FUNC_PARAMS);
IntPtr ber_tlv_decode_RSAPrivateKey(BER_TLV_DECODING_FUNC_PARAMS);
IntPtr ber_tlv_export_RSAPublicKey(BER_TLV_ENCODING_FUNC_PARAMS);
IntPtr ber_tlv_encode_RSAPublicKey(BER_TLV_ENCODING_FUNC_PARAMS);
IntPtr ber_tlv_decode_RSAPublicKey(BER_TLV_DECODING_FUNC_PARAMS);

#endif /* MySuiteA_rsa_codec_der_h */
