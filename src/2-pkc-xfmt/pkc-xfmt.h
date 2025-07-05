/* DannyNiu/NJF, 2025-06-14. Public Domain. */

#ifndef MySuiteA_pkc_xfmt_h
#define MySuiteA_pkc_xfmt_h 1

// 2025-06-15.
// Conversion of cryptogram format is considered by this project as an
// offline / out-of-band operation, as such, there is no consideration for
// side-channel protection.
// Also, error checking of source key formats (e.g. dupilcate and out-of-order
// JSON indicies, uncertain whitespaces in JWK, leading zeros, etc.) make it
// more difficult to process foreign formats, thus the decision.

#include "../mysuitea-common.h"

typedef struct {
    int32_t     component;
    int32_t     offset;

    // `position` == p * 16 + s * 5 + l , where
    // - p is the position of the initial byte of `cache` in the component;
    //   with any encoding scheme removed.
    // - s is the encoding scheme:
    //   - 0 means no encoding applied,
    //   - 1 means hexadecimal,
    //   - 2 means url-safe base64 without padding character.
    // - l is the number of content bytes in `cache`.
    // If the value 15 (i.e. 0xf) for the expression s * 15 + l is reserved.
    //
    // Implementation (and usage) note:
    // Decoder providers should treat position value 0 as uninitialized,
    // and attempt to initialize it where possible. For any non-identity
    // encoding, this member will become non-zero once initialized;
    // for identity encoding (i.e. no encoding), l will be in 1 through 4
    // inclusive if there's any data - if the component turns out to be
    // of zero-length, an immediate return of -1 from any
    // `pkc_xfmt_readbyte_t` function will notify the caller to
    // not read from it anymore, thus in normal operation, there
    // shouldn't be chance for infinite loop.
    // As such, zero-initializing this structure is the way to do.
    int32_t     position;
    uint8_t     cache[4];
} pkc_xfmt_accel_t;

int (*pkc_xfmt_readbyte_t)(
    const void *restrict src, size_t srclen,
    pkc_xfmt_accel_t *restrict accel,
    int32_t component, int32_t position,
    CryptoParam_t *restrict algoparams);

int XfmtReadByteFromBase64URL(
    const void *restrict src, size_t srclen,
    pkc_xfmt_accel_t *restrict accel,
    int32_t component, int32_t position,
    CryptoParam_t *restrict algoparams);

int XfmtReadByteFromBERInteger(
    const void *restrict src, size_t srclen,
    pkc_xfmt_accel_t *restrict accel,
    int32_t component, int32_t position,
    CryptoParam_t *restrict algoparams);

// So as to be compatible with textual data.
// Can change to `uint8_t` if wanted.
typedef char byte;

// Working context for writing and reading JSON strings.
//
// It is discovered during API engineering that, JSON readers
// often required copying immutable values of this structure
// to new variables while retaining the values in the original
// variables; whereas JSON writers needed mutable variables
// to do bookkeeping.
//
typedef struct {
    // Pointer to JSON data.
    // Can be NULL during writing if full length isn't known yet.
    union {
        byte *json;
        byte const *str;
    };

    // The length of JSON string pointed to by `json`/`str`.
    // Reader won't read beyond this limit, and if not set appropriately,
    // reading error can occur.
    // Writer will also ignore this variable unless `json` is non-NULL.
    size_t limit;

    // The current reading/writing offset into the JSON string.
    size_t offset;

    // Carries function-defined return value
    // for communicating between caller and callee.
    IntPtr info;
} json_io_t;

json_io_t *json_putc(json_io_t *ctx, int c);
int json_getc(json_io_t *ctx);
int json_peek(json_io_t *ctx);
void json_incr(json_io_t *ctx);

json_io_t XfmtJson_Skip1Value(json_io_t JsonValue);
json_io_t XfmtJson_FindIndexInArray(json_io_t JsonValue, long index);
json_io_t XfmtJson_ScanObjectForKey(json_io_t JsonValue, const byte *key);
json_io_t XfmtJson_FindStringEnd(json_io_t JsonValue);
json_io_t XfmtJson_Skip1String(json_io_t JsonValue);
json_io_t XfmtJson_SkipWhitespace(json_io_t JsonValue);

#define XfmtJson_Skip1Array(jv)  XfmtJson_FindIndexInArray(jv, -1)
#define XfmtJson_Skip1Object(jv) XfmtJson_ScanObjectForKey(jv, NULL)

int JsonStringSameWithCString(json_io_t JsonValue, const byte *cstr);

bool XfmtJson_LintObject(json_io_t JsonValue);

IntPtr BERIntegerFromBase64URL(json_io_t jstr, uint8_t *enc, size_t enclen);

json_io_t *UIntBase64URLCopyOctetString(
    json_io_t *jctx, const uint8_t *enc, size_t enclen);
json_io_t *UIntBase64URLTrimOctetString(
    json_io_t *jctx, const uint8_t *enc, size_t enclen);

#endif /* MySuiteA_pkc_xfmt_h */
