/* DannyNiu/NJF, 2022-08-05. Public Domain. */

#include "TCrew-Stub.h"
#include <time.h>

int TCrew_Stub_Init(TCrew_Stub_t *crew)
{
    int ret = TCrew_RetOk;

    // initialize functions table.
    crew->funcstab.enqueue = (TCrew_Dispatch_t)TCrew_Stub_Task_Enqueue;
    crew->funcstab.wait = (TCrew_Dispatch_t)TCrew_Stub_Task_Enqueue;
    return ret;
}

int TCrew_Stub_Task_Enqueue(
    TCrew_Stub_t *crew,
    TCrew_Assignment_t func, void *ctx)
{
    (void)crew;

    if( func ) func(ctx);
    return 0;
}

TCrew_Stub_t tcrew_stub = {
    .funcstab.enqueue = (TCrew_Dispatch_t)TCrew_Stub_Task_Enqueue,
    .funcstab.wait    = (TCrew_Dispatch_t)TCrew_Stub_Task_Enqueue,
};
