/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#ifndef MySuiteA_ecdh_kem_h
#define MySuiteA_ecdh_kem_h 1

#include "sec1-common.h"

// In a typical Diffie-Hellman-like key exchange, each peer operates
// identically, i.e. that being peer-symmetric. However, some post-quantum
// PKE/KEM schemes the operation is peer-asymmetric.
//
// For code-based PKEs, it's because the encrypting peer is applying
// different operation than the decrypting peer; for lattice-based KEMs,
// the Fujisaki-Okamoto transformation dictates that the decrypting peer
// must do different additional work to verify that the ciphertext is
// not one that would tricks the decrypting oracle with methods like
// decryption failure amplification to guess private key bits.
//
// Additionally, it is intended that MySuiteA provide a uniform interface
// across all algorithms of same type - KEM is a more general form than
// key-agreement (and PKE) in terms of API design. And RSA encryption cannot
// fit in the form of key-agreement.
//
// All in all, ECDH is implemented as a KEM. And, the documents in the
// suite describe ECDH as ECDH-KEM to emphasize that it's not implemented
// in the form of a traditional key-agreement API.

typedef SEC1_Common_Priv_Ctx_Hdr_t ECDH_KEM_Priv_Ctx_Hdr_t;

#endif /* MySuiteA_ecdh_kem_h */
