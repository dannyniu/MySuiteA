/* DannyNiu/NJF, 2022-02-05. Public Domain. */

#ifndef MySuiteA_ecc_curves_secp_h
#define MySuiteA_ecc_curves_secp_h 1

#include "ecp-xyz.h"

extern const ecp_curve_t *secp256r1;
extern const ecp_curve_t *secp384r1;

#define c_secp256r1(q) c_Curve(q,256)
#define c_secp384r1(q) c_Curve(q,384)

#define x_secp256r1(q) x_Curve(q,256,NameFactory_SECP_R)
#define x_secp384r1(q) x_Curve(q,384,NameFactory_SECP_R)

IntPtr i_secp256r1(int q);
IntPtr i_secp384r1(int q);

#endif /* MySuiteA_ecc_curves_secp_h */
