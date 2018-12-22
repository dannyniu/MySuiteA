/* DannyNiu/NJF, 2018-01-30. Public Domain. */

#include <endian.h>

#ifndef __APPLE__ // who as of macOS 10.14 Mojave don't have <endian.h>
#define MySuiteA_endian_h 0
#endif /* __APPLE__ */

#ifndef MySuiteA_endian_h
#define MySuiteA_endian_h 1

#include <stdint.h>

// Endian-Test Preprocessor Macros. 

#define LITTLE_ENDIAN   1234
#define BIG_ENDIAN      4321

#undef BYTE_ORDER

#if defined(__i386__) || defined(__x86_64__) || ( defined(__ARM_ACLE) && !__ARM_BIG_ENDIAN )
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#if ( defined(__ARM_ACLE) && __ARM_BIG_ENDIAN )
#define BYTE_ORDER BIG_ENDIAN
#endif

// Byte-Swapping Macros. 

#ifdef __ARM_ACLE

#include <arm_acle.h>

#define __bswap16(x) ((uint16_t)__rev16(x))
#define __bswap32(x) ((uint32_t)__rev(x))
#define __bswap64(x) ((uint64_t)__revll(x))

#else // No built-in byte-swapping intrinsics.

uint16_t __bswap16(uint16_t x);
uint32_t __bswap32(uint32_t x);
uint64_t __bswap64(uint64_t x);

#endif

// The Endian-Swapping Macros. 

#if BYTE_ORDER == LITTLE_ENDIAN

#define htobe16(x) (__bswap16(x))
#define htole16(x) (x)
#define be16toh(x) (__bswap16(x))
#define le16toh(x) (x)

#define htobe32(x) (__bswap32(x))
#define htole32(x) (x)
#define be32toh(x) (__bswap32(x))
#define le32toh(x) (x)

#define htobe64(x) (__bswap64(x))
#define htole64(x) (x)
#define be64toh(x) (__bswap64(x))
#define le64toh(x) (x)

#elif BYTE_ORDER == BIG_ENDIAN

#define htobe16(x) (x)
#define htole16(x) (__bswap16(x))
#define be16toh(x) (x)
#define le16toh(x) (__bswap16(x))

#define htobe32(x) (x)
#define htole32(x) (__bswap32(x))
#define be32toh(x) (x)
#define le32toh(x) (__bswap32(x))

#define htobe64(x) (x)
#define htole64(x) (__bswap64(x))
#define be64toh(x) (x)
#define le64toh(x) (__bswap64(x))

#else
#error Your host byte order is not supported!
#endif

#endif /* MySuiteA_endian_h */
