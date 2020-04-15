#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

//New mission 2: argument passing.
#define ARGS_DELIMITER " "
#define ARGS_MAX 50
#define ARGS_LEN_MAX 100

//New mission 3: syscall.
#define EXEC 1  // First type of inter process comminication.
#define WAIT 0  // Second type of inter process communication.
#define READ 1
#define WRITE 0

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void init_ipc(void);
#endif /* userprog/process.h */
