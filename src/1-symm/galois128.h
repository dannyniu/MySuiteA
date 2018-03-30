/* DannyNiu/NJF, 2018-02-11. Public Domain. */

#include "../mysuitea-common.h"

// References: src/notes.txt: "GCM - Galois Counter Mode". 

void galois128_hash1block(void *restrict Y, // Accumulator. 
                          const void *restrict H, // Hashing Key. 
                          const void *restrict X); // message block. 
