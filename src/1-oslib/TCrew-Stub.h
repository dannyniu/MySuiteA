/* DannyNiu/NJF, 2022-08-05. Public Domain. */

#ifndef THREADS_CREW_STUB_H
#define THREADS_CREW_STUB_H 1

#include <errno.h>
#include <stdbool.h>
#include "TCrew-common.h"

#define TCrew_RetOk 0

typedef struct TCrew_Stub {
    TCrew_Abstract_t funcstab;
} TCrew_Stub_t;

// Initialize a stub threads crew.
int TCrew_Stub_Init(TCrew_Stub_t *crew);

// Call a function.
int TCrew_Stub_Task_Enqueue(
    TCrew_Stub_t *crew,
    TCrew_Assignment_t func, void *ctx);

extern TCrew_Stub_t tcrew_stub;

#endif /* THREADS_CREW_STUB_H */
