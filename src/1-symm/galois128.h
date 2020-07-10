/* DannyNiu/NJF, 2018-02-11. Public Domain. */

#include "../mysuitea-common.h"

// References: src/notes.txt: "GCM - Galois Counter Mode". 

void galois128_hash1block(void *restrict Y, // Accumulator. 
                          void const *restrict H, // Hashing Key. 
                          void const *restrict X); // message block. 
