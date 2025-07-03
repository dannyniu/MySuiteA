/* DannyNiu/NJF, 2021-01-13. Public Domain. */

#ifndef MySuiteA_rsa_codec_kwt_h
#define MySuiteA_rsa_codec_kwt_h 1

#include "../2-pkc-xfmt/pkc-xfmt.h"

json_io_t *RSAPrivateKey_ToJWK(
    json_io_t *jctx, const uint8_t *enc, size_t enclen);

IntPtr RSAPrivateKey_FromJWK(
    json_io_t jstr, uint8_t *enc, size_t enclen);

#endif /* MySuiteA_rsa_codec_kwt_h */
