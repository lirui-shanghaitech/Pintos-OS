#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Using the first method to check pointer, check pintos manual. */
#include "pagedir.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
static bool is_valid_vaddr (const void *ptr);
static bool is_valid_str (const void *ptr);
static void check_string(const void *ptr);

/* The entry of system call function, a function pionter arrays, 
   All syscall is wrapped as the same formate since, the input parameter can be obtained from stack,
  whereas the retrun value puts to eax registor. */
static int (*sysc_handlers[20]) (struct intr_frame *);

// TODO: For all the stub function remember to check the validity of input pointer, reference.

/* This struct is the element defined in thread.h file_table, it is used to
  retrieve file pointer given file descriptor: fd */
typedef struct fd_elem 
{
  struct file *file;
  struct list_elem elem;
  int fd;
} fd_elem;


/* A wrapper function of thread_exit(), since we want to store the status value
  to the thread_current()->ret. */
void
thread_exit_wrapper(int status)
{
  thread_current()->ret = status;
  thread_exit();
}


/* Auxiliary function: this function returns the file pointer from current thread's
  file_table, given the file descriptor fd, return NULL if did not find matching element */
static fd_elem* 
get_fd_elem(int fd)
{
  struct list_elem *e;
  struct thread *t = thread_current();
  // Traverse file_table find the file element.
  for (e = list_begin(&t->file_table); e!=list_end(&t->file_table); e=list_next(e))
  {
    fd_elem* fe = list_entry(e, fd_elem, elem);
    if (fe->fd == fd)
      return fe;
  }
  // If did not find, return NULL.
  return NULL;
}

/* Auxiliary function: this function writes size bytes from buffer to the open file fd,
  returns the number of bytes actually written, which may be less than the size if some
  bytes could not be written. Note fd == 1, means we need to write to console*/
static int 
syscall_write_auxi(int fd, const void *buff, unsigned size)
{
  if (fd == STDOUT_FILENO)
  {
    /* If fd is standard output, write to console. */
    putbuf((char *)buff, size);
    return (int) size;
  } else
  {
    /* If fd is a file, write to that file. */
    fd_elem *fe = get_fd_elem(fd);
    if (!(fe == NULL))
      return (int) file_write(fe->file, buff, size);
  }
  return -1;
}

/* Auxiliary function: this function reads size bytes from the file open as fd into buffer,
  returns the number of bytes actually read(0 at end of file), or -1 if the file could not be 
  read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc().*/
static int 
syscall_read_auxi(int fd, const void *buff, unsigned size)
{
  if (fd == STDIN_FILENO)
  {
    /* If fd is standard input, reads from the keyboard. */    
    for (int i = 0; i < size; i++)
    {
      input_getc();
    }   
    return (int) size;
  } else
  {
    /* If fd is a file, write to that file. */
    fd_elem *fe = get_fd_elem(fd);
    if (!(fe == NULL))
      return (int) file_read(fe->file, buff, size);
  }
  return -1;
}

/* Auxiliary function: this function close a single file given the file descriptor. */
static void 
syscall_close_auxi(int fd)
{
  fd_elem *fe = get_fd_elem(fd);
  if (!(fe == NULL))
  {
    // Close a single file.
    file_close(fe->file);
    // Remove from file table and free memory.
    list_remove(&fe->elem);
    free(fe);
  }
}

/* Auxiliary function: this function close all the file, which this process previously
  opened, note that here we did not close the executable file. */
void 
syscall_close_all_auxi(void)
{
  struct thread *cur_t = thread_current();
  //  Close all the open file.
  while(!list_empty(&cur_t->file_table))
  {
    fd_elem *fe = list_entry(list_pop_front(&cur_t->file_table), fd_elem, elem);
    file_close(fe->file);
    free(fe);
  }

  // Clean the file_number, thus, next time it will start from 0.
  cur_t->file_number = 2;
}


static void
syscall_halt_stub(struct intr_frame *f)
{
  //TODO: HALT system call.
  shutdown();
  return;
}

static void
syscall_exit_stub(struct intr_frame *f)
{
  //TODO: EXIT system call.
  if (!is_valid_vaddr(((int *)f->esp)+1))
  {
    thread_exit_wrapper(-1);
    return;
  }
  thread_current()->ret = *(((int *)f->esp)+1);
  f->eax = 0;
  thread_exit();
  return;
}

static void
syscall_exec_stub(struct intr_frame *f)
{
  //TODO: EXEC system call.
  char *fn_copy = *(char **)(f->esp+4);
  
  // Here we use another copy is because we can not change file_name.
  char *fn_copy_two = (char *) malloc ((strlen(fn_copy)+1)*sizeof(char));
  if (fn_copy_two == NULL)
    return;
  memcpy (fn_copy_two, fn_copy, strlen(fn_copy)+1);
  f->eax = process_execute(fn_copy_two);
  free(fn_copy_two);
  return;
}

static void
syscall_wait_stub(struct intr_frame *f)
{
  //TODO: WAIT system call.
  // Check pointer.
  if (!is_user_vaddr(((int *)f->esp)+1))
  {
    thread_exit_wrapper(-1);
    return;
  }
  // Call process_wait().
  int pid = -1;
  pid = *(((int *)f->esp)+1);
  f->eax = process_wait(pid);
  return;
}

static void
syscall_create_stub(struct intr_frame *f)
{
  //TODO: CREATE system call.

  if (!is_valid_vaddr(f->esp + 4) || !is_valid_vaddr(f->esp + 8))
  {
    thread_exit_wrapper(-1); 
    return;  
  }

  if (!is_valid_str(f->esp + 4))
  {
    thread_exit_wrapper(-1); 
    return;
  }
   
  char* file = *(char **)(f->esp+4);
  unsigned size = *(unsigned *)(f->esp+8);
  f->eax = filesys_create(file,size);
  return;
}

static void
syscall_remove_stub(struct intr_frame *f)
{
  //TODO: REMOVE system call.
  if (!is_valid_vaddr(f->esp + 4))
  {
    thread_exit_wrapper(-1); 
    return;  
  }

  if (!is_valid_str(f->esp + 4))
  {
    thread_exit_wrapper(-1); 
    return;
  }

  char* file = *(char **)(f->esp+4);
  f->eax = filesys_remove(file);
  return;
}

static void
syscall_open_stub(struct intr_frame *f)
{
  //TODO: OPEN system call.
  if (!is_valid_vaddr(f->esp + 4))
  {
    thread_exit_wrapper(-1); 
    return;  
  }
  if (!is_valid_str(f->esp + 4))
  {
    thread_exit_wrapper(-1); 
    return;  
  }

  char* file = *(char **)(f->esp+4);
  struct fd_elem *fd_elem = malloc(sizeof(struct fd_elem));
  fd_elem -> file = filesys_open(file);
  if (fd_elem -> file == NULL)
  {
    f-> eax = -1;
    // thread_exit_wrapper(-1); 
    return;
  }
  
  struct thread *cur_t = thread_current();
  cur_t -> file_number += 1;
  fd_elem->fd = cur_t -> file_number;
  f-> eax = fd_elem->fd;
  list_push_back(&cur_t->file_table, &fd_elem->elem);
  return;
}

static void 
syscall_filesize_stub(struct intr_frame *f)
{
  //TODO: FILESIZE system call.
  if (!is_valid_vaddr(f->esp + 4))
  {
    thread_exit_wrapper(-1); 
    return;  
  }

  int fd = *(int *)(f->esp+4);
  if(get_fd_elem(fd) == NULL)
  {
    thread_exit_wrapper(-1); 
    return;
  }
  struct fd_elem *fd_elem = get_fd_elem(fd);
  f->eax = file_length(fd_elem->file);
  return;
}

static void
syscall_read_stub(struct intr_frame *f)
{
  //TODO: READ system call.

  int fd = *(((int *)(f->esp))+1);
  void *buffer = *(char **)(f->esp+8);
  unsigned size = *(unsigned *)(f->esp+12);

  if (!is_user_vaddr(f->esp + 4))
  {
    thread_exit_wrapper(-1);
    return;
  }

  // Check buffer.
  if (!is_user_vaddr(buffer))
  {
    thread_exit_wrapper(-1);
    return;
  }

  f->eax = syscall_read_auxi(fd, buffer, size);
  return;
}

static void
syscall_write_stub(struct intr_frame *f)
{
  //TODO: WRITE system call.
  int fd = *(((int *)(f->esp))+1);
  void *buffer = *(char **)(f->esp+8);
  unsigned size = *(unsigned *)(f->esp+12);
  // Check pointer.
  if (!is_user_vaddr(f->esp + 4))
  {
    thread_exit_wrapper(-1);
    return;
  }
  // Write to file.
  f->eax = syscall_write_auxi(fd, buffer, size);
  return;
}

static void
syscall_seek_stub(struct intr_frame *f)
{
  //TODO: SEEK system call.
  if (!is_valid_vaddr(f->esp + 4) || !is_valid_vaddr(f->esp + 8))
  {
    thread_exit_wrapper(-1); 
    return;  
  }   
  int fd = *(int *)(f->esp+4);
  unsigned position = *(unsigned *)(f->esp+8);
  struct fd_elem *fd_elem = get_fd_elem(fd);
  file_seek(fd_elem->file,position);
  return;
}

static void
syscall_tell_stub(struct intr_frame *f)
{
  //TODO: TELL system call.
  if (!is_valid_vaddr(f->esp + 4))
  {
    thread_exit_wrapper(-1); 
    return;  
  }   
  int fd = *(int *)(f->esp+4);
  struct fd_elem *fd_elem = get_fd_elem(fd);
  f->eax = file_tell(fd_elem->file);
  return;
}

static void
syscall_close_stub(struct intr_frame *f)
{
  //TODO: CLOSE system call.
  if (!is_valid_vaddr(f->esp + 4))
  {
    thread_exit_wrapper(-1); 
    return;  
  }   
  int fd = *(int *)(f->esp+4);
  struct fd_elem *fd_elem = get_fd_elem(fd);
  if (fd_elem != NULL)
  {
    file_close(fd_elem->file);
    list_remove(&fd_elem->elem);
    free(fd_elem);
  } else
  {
    thread_exit_wrapper(-1); 
    return;
  }
  return;  
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  // Init the system call function pinter array:
  sysc_handlers[SYS_HALT] = &syscall_halt_stub;
  sysc_handlers[SYS_EXIT] = &syscall_exit_stub;
  sysc_handlers[SYS_EXEC] = &syscall_exec_stub;
  sysc_handlers[SYS_WAIT] = &syscall_wait_stub;
  sysc_handlers[SYS_CREATE] = &syscall_create_stub;
  sysc_handlers[SYS_REMOVE] = &syscall_remove_stub;
  sysc_handlers[SYS_OPEN] = &syscall_open_stub;
  sysc_handlers[SYS_FILESIZE] = &syscall_filesize_stub;
  sysc_handlers[SYS_READ] = &syscall_read_stub;
  sysc_handlers[SYS_WRITE] = &syscall_write_stub;
  sysc_handlers[SYS_SEEK] = &syscall_seek_stub;
  sysc_handlers[SYS_TELL] = &syscall_tell_stub;
  sysc_handlers[SYS_CLOSE] = &syscall_close_stub;
}

static void
syscall_handler (struct intr_frame *f) 
{
  //TODO: Check if it is a valide pointer, and whether the syscall_num is valid.
  // Check the pointer.
  if (!is_user_vaddr(f->esp))
  {
    thread_exit_wrapper(-1);
    return;
  }

  //Extract the system call number, and run the syscall.
  int sysc_num = *((int *)f->esp);

  // Check the syscall number.
  if (sysc_num >= 20 || sysc_num < 0)
  {
    thread_exit_wrapper(-1);
    return;
  }

  int ret = sysc_handlers[sysc_num](f);

}

/* The following functions are used to protect kernal from malicious pointer. */

/* Check the if it is a valid virtual address given the pinter. */
static bool
is_valid_vaddr(const void *ptr)
{
  if (!is_user_vaddr(ptr))
  {
    return false;
  }
  return true;
}

static bool
is_valid_str(const void *ptr)
{
  char *str_ptr = *(char**)ptr;
  if (str_ptr == NULL)
  {
    return false;
  }
  return true;
}

static void
check_string(const void *ptr)
{
  char *pt = (char *)ptr;
  if (!is_user_vaddr(pt))
    thread_exit_wrapper(-1);
  // Find '\0', if we didn't find it until the page boundary, exit.
  while(pagedir_get_page(thread_current()->pagedir, (void *)pt))
  {
    if (*pt == '\0')
      return;
    pt++;
  }
  thread_exit_wrapper(-1);
}