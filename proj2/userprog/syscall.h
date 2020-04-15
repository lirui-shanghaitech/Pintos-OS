#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
/* New mission 3: syscall for process_exit() */
void syscall_close_all_auxi(void);
void thread_exit_wrapper(int);
void init_ipc(void);
#endif /* userprog/syscall.h */
