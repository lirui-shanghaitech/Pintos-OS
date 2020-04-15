#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore 
  {
    unsigned value;             /* Current value. */
    struct list waiters;        /* List of waiting threads. */
  };

void sema_init (struct semaphore *, unsigned value);
void sema_down (struct semaphore *);
bool sema_try_down (struct semaphore *);
void sema_up (struct semaphore *);
void sema_self_test (void);

/* Lock. */
struct lock 
  {
    /* New mission 2: Record the max donor priority, used in priority donation, updata when
      1. in lock_acquire(), the donation happens, updata as priority of current thread. */
    int donor_max_priority;

    /* New mission 2: Using for struct list locks defined in struct thread */
    struct list_elem elem;

    struct thread *holder;      /* Thread holding lock (for debugging). */
    struct semaphore semaphore; /* Binary semaphore controlling access. */
  };

void lock_init (struct lock *);
void lock_acquire (struct lock *);
bool lock_try_acquire (struct lock *);
void lock_release (struct lock *);
bool lock_held_by_current_thread (const struct lock *);

/* Condition variable. */
struct condition 
  {
    struct list waiters;        /* List of waiting threads. */
  };

void cond_init (struct condition *);
void cond_wait (struct condition *, struct lock *);
void cond_signal (struct condition *, struct lock *);
void cond_broadcast (struct condition *, struct lock *);

/* Our code */

/* New mission 2: monitor compare function, not that the element of 
  the cond->waiter is a semaphore who still has a waiting priority list. */
bool cond_compare_priority(const struct list_elem *l, const struct list_elem *r, void *aux);

/* New mission 2: compare the priority of lock's donor_max_priority */
bool lock_compare_priority (const struct list_elem *l, const struct list_elem *r, void *aux);


/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile ("" : : : "memory")

#endif /* threads/synch.h */
