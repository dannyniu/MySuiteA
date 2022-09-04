/* DannyNiu/NJF, 2022-08-17. Public Domain. */

#ifndef THREADS_CREW_COMMON_H
#define THREADS_CREW_COMMON_H

typedef void (*TCrew_Assignment_t)(void *ctx);

typedef int (*TCrew_Dispatch_t)(
    void *crew, TCrew_Assignment_t func, void *ctx);

// ``TCrew_Abstract_t'' is an abstract type containing a functions table
// from some concrete threads crew class. The way a threads crew class
// is initialized is unspecified.
typedef struct
{
    // # BEHAVIOR:
    // The ``TCrew_Abstract_t::enqueue'' function enqueues a job on the
    // threads crew. When the job is executed, the ``func'' function
    // is called with ``ctx'' as its only parameter.
    //
    // # RETURN VALUE:
    // It returns 0 on success.
    //
    // # IMPLEMENTATION DETAIL:
    // In this implementation, the function does not return until
    // some crew member accepts the job.
    TCrew_Dispatch_t enqueue;

    // # BEHAVIOR:
    // The ``TCrew_Abstract_t::wait'' function shall execute the
    // ``func'' function with ``ctx'' as its only parameter.
    // Before the function is executed, if there's any job that had
    // not yet completed, wait shall block until all such jobs had
    // completed. If while a call to wait is underway, another call
    // to wait or enqueue is made, then the behavior is undefined.
    //
    // # RETURN VALUE:
    // Returns the number of jobs completed (>=0), or -1 on failure.
    TCrew_Dispatch_t wait;
} TCrew_Abstract_t;

#endif /* THREADS_CREW_COMMON_H */
