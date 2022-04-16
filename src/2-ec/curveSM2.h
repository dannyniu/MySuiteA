/* DannyNiu/NJF, 2022-04-16. Public Domain. */

#ifndef MySuiteA_ecc_curveSM2_h
#define MySuiteA_ecc_curveSM2_h 1

#include "ecp-xyz.h"

extern const ecp_curve_t *curveSM2;

#define c_curveSM2(q) c_Curve(q,256)
#define x_curveSM2(q) x_Curve(q,256,NameFactory_SM2)

#define NameFactory_SM2(bits) curveSM2

IntPtr i_curveSM2(int q);

#endif /* MySuiteA_ecc_curveSM2_h */
