/* DannyNiu/NJF, 2020-11-29. Public Domain. */

#include "../test-utils.c.h"

#include "ctr-drbg.c"
#include "hmac-drbg.c"

#include "../1-symm/rijndael.c"

int testing_enabled;
size_t EntropyBits, NonceBits, PersonalBits, AdditionalBits, ReturnedBits;

uint8_t SeedStr[128]; // 1024 bits.
uint8_t ReturnedData[256]; // 2048 bits.
char InputLine[1024];

union {
    ctr_drbg_t drbg_ctr;
    hmac_drbg_t drbg_hmac;
} *drbg_ctx;
