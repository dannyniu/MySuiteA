/* DannyNiu/NJF, 2018-01-30. Public Domain. */

#ifndef MySuiteA_endian_h
#define MySuiteA_endian_h 1

#include <stdint.h>

#undef MySuiteA_UsePlatformEndianFuncs

#ifdef __has_include
#if __has_include(<endian.h>)
#include <endian.h>
#define MySuiteA_UsePlatformEndianFuncs 1
#endif /* __has_include(<endian.h>) */
#endif /* __has_include */

#ifndef MySuiteA_UsePlatformEndianFuncs

uint16_t htobe16(uint16_t);
uint32_t htobe32(uint32_t);
uint64_t htobe64(uint64_t);

uint16_t be16toh(uint16_t);
uint32_t be32toh(uint32_t);
uint64_t be64toh(uint64_t);

uint16_t htole16(uint16_t);
uint32_t htole32(uint32_t);
uint64_t htole64(uint64_t);

uint16_t le16toh(uint16_t);
uint32_t le32toh(uint32_t);
uint64_t le64toh(uint64_t);

#endif /* MySuiteA_UsePlatformEndianFuncs */

#endif /* MySuiteA_endian_h */
