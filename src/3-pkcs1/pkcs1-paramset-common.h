/* DannyNiu/NJF, 2023-08-09. Public Domain. */

#ifndef MySuiteA_pkcs1_paramset_common_h
#define MySuiteA_pkcs1_paramset_common_h 1

#include "pkcs1.h"
#include "../2-hash/sha.h"
#include "../2-xof/shake.h"

PKCS1_RSA_Param_t PKCS1_RSA_With_SHA256, PKCS1_RSA_With_SHAKE128;

#endif /* MySuiteA_pkcs1_paramset_common_h */
