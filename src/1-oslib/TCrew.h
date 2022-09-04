/* DannyNiu/NJF, 2022-08-05. Public Domain. */

#ifndef THREADS_CREW_H
#define THREADS_CREW_H 1

#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
#include "TCrew-common.h"

// This is the value from POSIX. For C11 threads, it's ``thrd_success''.
#define TCrew_RetOk 0

// These are the types from POSIX. C11 has equivalents.
#define TCrewThread_t       pthread_t
#define TCrewMutex_t        pthread_mutex_t
#define TCrewCondVar_t      pthread_cond_t

typedef void *TCrewThread_ExitVal_t;
typedef TCrewThread_ExitVal_t (*TCrewThread_Func_t)(void *);

#define TCrewThread_Create(hndl,func,arg)       \
    pthread_create(hndl, NULL, func, arg)

#define TCrewThread_Detach(hndl)        pthread_detach(hndl)
#define TCrewThread_Join(hndl,res)      pthread_join(hndl, res)
#define TCrewThread_Exit(val)           pthread_exit(val)

#define TCrewMutex_Init(mtx)            pthread_mutex_init(mtx, NULL)
#define TCrewMutex_Destroy(mtx)         pthread_mutex_destroy(mtx)
#define TCrewMutex_Lock(mtx)            pthread_mutex_lock(mtx)
#define TCrewMutex_Unlock(mtx)          pthread_mutex_unlock(mtx)

#define TCrewCondVar_Init(cnd)          pthread_cond_init(cnd, NULL)
#define TCrewCondVar_Destroy(cnd)       pthread_cond_destroy(cnd)
#define TCrewCondVar_Broadcast(cnd)     pthread_cond_broadcast(cnd)
#define TCrewCondVar_Signal(cnd)        pthread_cond_signal(cnd)
#define TCrewCondVar_Wait(cnd,mtx)      pthread_cond_wait(cnd,mtx)

// Compilation-time capability specification.
#define TCREW_THREADS_MAX 64
#define TCREW_TLEN 4

// ThreadsCrew API type definitions..
typedef struct TCrew TCrew_t;

typedef struct TCrewMember {
    TCrewThread_t thread_handle;
    
    // signalled by ``TCrew_Task_Enqueue'' to
    // wake up the thread.
    TCrewCondVar_t wake;

    // When a task is executing.
    int busy;

    // current (positive) position in the polling timespecs.
    // -1 indicates this member is not running a thread.
    // distinction is made between a crew member and a thread.
    int poll_index;
    
    struct timespec poll_rt[TCREW_TLEN]; // last few samples of real time.
    struct timespec poll_tt[TCREW_TLEN]; // last few samples of thread time.

    TCrew_Assignment_t taskproc; void *taskproc_ctx;

    // -- changed to wait on main thread. --
    // TCrew_Assignment_t callback; void *callback_ctx;

    TCrew_t *crew;
} TCrewMember_t;

struct TCrew {
    TCrew_Abstract_t funcstab;
    
    int cntCompleted; // used by ``TCrew_Abstract_t::wait''
    int cntEnqueued; // set by ``TCrew_Abstract_t::enqueue''

    // The big mutex that protects the invariant of the entire crew.
    TCrewMutex_t lockCrew;

    // Signalled by threads to inform ``TCrew_Task_Enqueue'' that
    // a crew member is available.
    TCrewCondVar_t avail;
    
    TCrewMember_t members[TCREW_THREADS_MAX];
};

// Initialize a threads crew.
int TCrew_Init(TCrew_t *crew);

// Finalize a threads crew.
void TCrew_Destroy(TCrew_t *crew);

// Asynchronously run a task.
int TCrew_Task_Enqueue(TCrew_t *crew, TCrew_Assignment_t func, void *ctx);

// When any task completes, ``func'' is executed with a single parameter ``ctx''.
int TCrew_Callback_Wait(TCrew_t *crew, TCrew_Assignment_t func, void *ctx);
    

#endif /* THREADS_CREW_H */
