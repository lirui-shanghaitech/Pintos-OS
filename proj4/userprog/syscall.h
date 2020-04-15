#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/kernel/list.h"
#include "filesys/file.h"

struct lock filesys_lock;

void syscall_init (void);
/* New mission 3: syscall for process_exit() */
void syscall_close_all_auxi(void);
void thread_exit_wrapper(int);
void init_ipc(void);
#endif /* userprog/syscall.h */
