/* DannyNiu/NJF, 2022-08-05. Public Domain. */

#include "TCrew.h"
#include <time.h>

TCrewThread_ExitVal_t TCrew_Thread_Loop(TCrewMember_t *self)
{
    int i;
    double u, v;
    struct timespec *poll_rt = self->poll_rt;
    struct timespec *poll_tt = self->poll_tt;
    
    do
    {
        // get task ready.
        TCrewMutex_Lock(&self->crew->lockCrew);
        while( !self->taskproc )
        {
            self->busy = false;
            TCrewCondVar_Broadcast(&self->crew->avail);
            TCrewCondVar_Wait(&self->wake, &self->crew->lockCrew);
            // ``self->busy'' should be set to 'true' by ``*_Enqueue''.
        }
        TCrewMutex_Unlock(&self->crew->lockCrew);

        // execute the task.
        self->taskproc(self->taskproc_ctx);
        self->taskproc = self->taskproc_ctx = NULL;

        // signal a waiting callback.
        TCrewMutex_Lock(&self->crew->lockCrew);
        self->crew->cntCompleted ++;
        TCrewMutex_Unlock(&self->crew->lockCrew);
        //- will broadcast after iteration of the loop.

        // update execution statistics.
        i = self->poll_index % TCREW_TLEN;
        clock_gettime(CLOCK_MONOTONIC,         poll_rt+i);
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, poll_tt+i);
        self->poll_index = (i + 1) % TCREW_TLEN;

        // decide if to destroy this thread and deactivate 'self'.
        if( self - self->crew->members < 2 )
            continue; // the first 2 threads are permanent within the crew.

        if( poll_rt[(i + 1) % TCREW_TLEN].tv_nsec < 0 ||
            poll_tt[(i + 1) % TCREW_TLEN].tv_nsec < 0 )
            continue;

        u =  poll_rt[i].tv_nsec - poll_rt[(i + 1) % TCREW_TLEN].tv_nsec;
        u /= 1.e+9;
        u += poll_rt[i].tv_sec  - poll_rt[(i + 1) % TCREW_TLEN].tv_sec;
        
        v =  poll_tt[i].tv_nsec - poll_tt[(i + 1) % TCREW_TLEN].tv_nsec;
        v /= 1.e+9;
        v += poll_tt[i].tv_sec  - poll_tt[(i + 1) % TCREW_TLEN].tv_sec;

        if( v / u < 0.25 ) // should relinquish resources.
        {
            TCrewMutex_Lock(&self->crew->lockCrew);
            
            for(i=0; i<TCREW_TLEN; i++)
            {
                poll_rt[i].tv_nsec = poll_tt[i].tv_nsec = -1;
            }

            self->busy = false;
            self->poll_index = -1;

            TCrewThread_Detach(self->thread_handle);
            TCrewMutex_Unlock(&self->crew->lockCrew);
            TCrewCondVar_Broadcast(&self->crew->avail);

            return (TCrewThread_ExitVal_t)0;
        }
        else continue; // should keep running.
    }
    while( true );
}

// This is only ever used by ``TCrew_Destroy''
// and ``TCrew_Init'' in case of its failure.
void TCrew_Task_ThreadExit(TCrewMember_t *self)
{
    TCrewMutex_Lock(&self->crew->lockCrew);
    self->busy = false;
    self->poll_index = -1;
    TCrewMutex_Unlock(&self->crew->lockCrew);
    TCrewThread_Exit((TCrewThread_ExitVal_t)0);
}

int TCrewMember_Init(TCrewMember_t *self, TCrew_t *crew)
{
    int i;
    int ret = TCrew_RetOk;
    
    if( (ret = TCrewCondVar_Init(&self->wake)) != TCrew_RetOk )
        return ret;

    self->busy = false;
    self->poll_index = -1;

    for(i=0; i<TCREW_TLEN; i++)
    {
        self->poll_rt[i].tv_nsec = self->poll_tt[i].tv_nsec = -1;
    }

    self->taskproc = self->taskproc_ctx = NULL;
    self->crew = crew;

    return ret;
}

void TCrewMember_Destroy(TCrewMember_t *self)
{
    int i;
    // int ret; // 2022-08-06: currently not used, but it might be used.
    
    TCrewCondVar_Destroy(&self->wake);

    self->busy = false;
    self->poll_index = -1;

    for(i=0; i<TCREW_TLEN; i++)
    {
        self->poll_rt[i].tv_nsec = self->poll_tt[i].tv_nsec = -1;
    }

    self->taskproc = self->taskproc_ctx = NULL;
    self->crew = NULL;
}

int TCrew_Init(TCrew_t *crew)
{
    int i;
    int ret = TCrew_RetOk;

    // initialize functions table.
    crew->funcstab.enqueue = (TCrew_Dispatch_t)TCrew_Task_Enqueue;
    crew->funcstab.wait = (TCrew_Dispatch_t)TCrew_Callback_Wait;
    crew->cntCompleted = 0;
    crew->cntEnqueued = 0;

    // initialize crew member structure fields.
    for(i=0; i<TCREW_THREADS_MAX; i++)
    {
        if( (ret = TCrewMember_Init(crew->members+i, crew)) != TCrew_RetOk )
        {
            goto rollback;
        }
    }

    // initialize crew synchronization objects.
    if( (ret = TCrewMutex_Init(&crew->lockCrew)) != TCrew_RetOk )
    {
        goto rollback;
    }

    if( (ret = TCrewCondVar_Init(&crew->avail)) != TCrew_RetOk )
    {
        TCrewMutex_Destroy(&crew->lockCrew);
        goto rollback;
    }

    // initialize first permanent thread.
    ret = TCrewThread_Create(
        &crew->members[0].thread_handle,
        (TCrewThread_Func_t)TCrew_Thread_Loop, &crew->members[0]);

    if( ret != TCrew_RetOk )
    {
        TCrewMutex_Destroy(&crew->lockCrew);
        TCrewCondVar_Destroy(&crew->avail);
        goto rollback;
    }

    crew->members[0].poll_index = 0;

    // initialize second permanent thread.
    ret = TCrewThread_Create(
        &crew->members[1].thread_handle,
        (TCrewThread_Func_t)TCrew_Thread_Loop, &crew->members[1]);

    if( ret != TCrew_RetOk )
    {
        TCrewMutex_Lock(&crew->lockCrew);
        crew->members[0].taskproc =
            (TCrew_Assignment_t)TCrew_Task_ThreadExit;
        crew->members[0].taskproc_ctx = &crew->members[0];
        TCrewMutex_Unlock(&crew->lockCrew);
        TCrewCondVar_Signal(&crew->members[0].wake);
        TCrewThread_Join(crew->members[0].thread_handle, NULL);
        
        TCrewMutex_Destroy(&crew->lockCrew);
        TCrewCondVar_Destroy(&crew->avail);
        goto rollback;
    }

    crew->members[1].poll_index = 0;

    // successful completion.
    return ret;

    // failure.
rollback:
    while( i-- )
    {
        TCrewMember_Destroy(crew->members+i);
    }
    return ret;
}

void TCrew_Destroy(TCrew_t *crew)
{
    int i;

    // prepare.
    TCrewMutex_Lock(&crew->lockCrew);
    
    // destroy all running threads.
    for(i=0; i<TCREW_THREADS_MAX; i++)
    {
        if( crew->members[i].poll_index >= 0 )
        {
            crew->members[i].taskproc =
                (TCrew_Assignment_t)TCrew_Task_ThreadExit;
            crew->members[i].taskproc_ctx = &crew->members[i];
        
            TCrewMutex_Unlock(&crew->lockCrew);
            TCrewCondVar_Signal(&crew->members[i].wake);
            TCrewThread_Join(crew->members[i].thread_handle, NULL);
            TCrewMutex_Lock(&crew->lockCrew);
        }
        else continue;
    }

    // deinitialize all crew members.
    for(i=0; i<TCREW_THREADS_MAX; i++)
    {
        TCrewMember_Destroy(crew->members+i);
    }

    // TCrewMutex_Destroy(&crew->lockCrew); // Do this last.
    TCrewCondVar_Destroy(&crew->avail);

    TCrewMutex_Unlock(&crew->lockCrew);
    TCrewMutex_Destroy(&crew->lockCrew);
}

int TCrew_Task_Enqueue(TCrew_t *crew, TCrew_Assignment_t func, void *ctx)
{
    int i;
    TCrewMember_t *cm;

    TCrewMutex_Lock(&crew->lockCrew);

    do
    {
        for(i=0; i<TCREW_THREADS_MAX; i++)
        {
            cm = crew->members + i;

            if( cm->busy ) continue; else break;
        }

        if( i < TCREW_THREADS_MAX ) break;
        TCrewCondVar_Wait(&crew->avail, &crew->lockCrew);
    }
    while( true );

    crew->cntEnqueued ++;
    cm->taskproc = func;
    cm->taskproc_ctx = ctx;
    
    if( cm->poll_index < 0 )
    {
        cm->poll_index = 0;
        
        TCrewThread_Create(
            &cm->thread_handle,
            (TCrewThread_Func_t)TCrew_Thread_Loop, cm);
    }

    cm->busy = true;
    TCrewMutex_Unlock(&crew->lockCrew);
    TCrewCondVar_Signal(&cm->wake);

    return 0;
}

int TCrew_Callback_Wait(TCrew_t *crew, TCrew_Assignment_t func, void *ctx)
{
    int ret = -1;
    
    if( TCrewMutex_Lock(&crew->lockCrew) != TCrew_RetOk )
        return -1;

    ret = crew->cntEnqueued;
    
    while( crew->cntCompleted < ret )
    {
        if( TCrewCondVar_Wait(&crew->avail, &crew->lockCrew) != TCrew_RetOk )
            return -1;
    }
    
    crew->cntCompleted -= ret;
    crew->cntEnqueued -= ret;
    if( func ) func(ctx);
    
    TCrewMutex_Unlock(&crew->lockCrew);
    return ret;
}
