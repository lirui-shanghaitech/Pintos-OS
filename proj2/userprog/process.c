#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "threads/malloc.h"
#include "threads/synch.h"
#include "syscall.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* New: mission 2:
  * Used for argument passing, the first extrace program name from file_string
  * the second one extract the arguments from command string, store at argv and argc
  * the third one puts the args in user program stack by 80x86 calling convention.
*/
static void extract_name(char *file_string, char *name, char *save_ptr);
static void extract_args(char *file_string, char *argv[], int *argc);
static char* put_args_to_stack(char *esp, char *argv[],  int argc);

/* New mission 3: 
  Used for syscall, this part is basically for inter process communication, we abstract
  it as a reader/writer problem, see the definition of function for description. */
typedef struct reader
{
  int pid_t;      // Identify the process
  struct semaphore sema;  // When read from empty list, sema_down.
  struct list_elem elem;  
} reader;

typedef struct writer
{
  int pid_t;  // Identify the process
  int stat;   // Record the child's pid or child's status.
  struct list_elem elem;
} writer;

/* Here we define two pairs of list, mainly because performace, thus when we use the first
  type ipc, we do not need to traverse the other type's list.  */
struct list read_exec_list;
struct list write_exec_list;
struct list read_wait_list;
struct list write_wait_list;

void init_ipc(void);
static int read_ipc(int mode, int pid_t);
static void write_ipc(int mode, int pid_t, int stat_t);

/* New mission 3: syscall. For recording the children of father process. */
typedef struct process_id
{
  int pid_t;
  struct list_elem elem;
} process_id;



/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  //TODO: Need to change this function.

  char *fn_copy;
  tid_t tid_x;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* New mission 2: argument passing, extract the file name here */
  /* Extract program name here. */
  char *name;
  char *save_ptr;
  name = strtok_r(file_name, ARGS_DELIMITER, &save_ptr);
  

  /* Create a new thread to execute FILE_NAME. */
  tid_x = thread_create (name, PRI_DEFAULT, start_process, fn_copy);
  
  // Updata and initialize the list and other properties.
  struct thread *c_t = thread_from_tid(tid_x);
  list_init(&c_t->children);    
  c_t->p_name = name;
  list_init(&c_t->file_table);
  // Start at 2, since 1 and 0 are already used as stdin, stdout.
  c_t->file_number = 2; 
  
  // For thread synchronization
  int temp_status = read_ipc(EXEC, tid_x);
  // TODO: When temp_status != -1, need to treat is as a child and push it to children list.
  if (temp_status != -1)
  {
    struct thread *cur_t = thread_current();
    process_id *child_p = malloc(sizeof(process_id));
    child_p->pid_t = temp_status;
    list_push_back(&cur_t->children, &child_p->elem);
  }

  return temp_status; 
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  // TODO: Need to change this function. Possible for Denying writes.

  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* New mission 1: argument passing */
  // Extract arguments here.
  char *argv[ARGS_MAX];
  int argc;
  extract_args(file_name, argv, &argc);
  char *name = argv[0];

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (name, &if_.eip, &if_.esp);


  /* If load failed, quit. */
  if (!success) 
  {
    // If load failed remember to release memory.
    palloc_free_page (file_name);
    // Write -1 to list stat, represent fail.
    write_ipc(EXEC, thread_current()->tid, -1);
    // Exit the process.
    thread_exit_wrapper(-1);
  }

  /* New mission 4: denying writes to executable. */
  thread_current()->self_file = filesys_open(name);
  file_deny_write(thread_current()->self_file);
    
  /* New mission 1: argument passing */
  // Push the arguments to stack.
  if_.esp = put_args_to_stack(if_.esp, argv, argc);
  // printf("Put args to stack!\n");
  
  // If success == true, pass the child's tid to children.
  struct thread *cur_t = thread_current();
  write_ipc(EXEC, cur_t->tid, cur_t->tid);
  // Remember to free the file_name_;
  palloc_free_page(file_name);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  // TODO: For now we change it to a inifinite loop, need to complete later.

  // First check if it is the real father of input child_tid.
  struct list_elem *em;
  struct thread *cur_t = thread_current();
  for (em=list_begin(&cur_t->children);em!=list_end(&cur_t->children);em=list_next(em))
  {
    process_id *pd = list_entry(em, process_id, elem);
    if (pd->pid_t == child_tid)
    {
      list_remove(em); // If it is the father of input pid, remove the child.
      int ipc_temp = read_ipc(WAIT, child_tid);
      return ipc_temp;
    } else   
    {
      return -1;  // If not the father return -1.
    }
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  //TODO: Need to change this function.

  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* New mission 3: wait syscall */
  write_ipc(WAIT, cur->tid, cur->ret);
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  printf ("%s: exit(%d)\n", cur->name, cur->ret);
  if (pd != NULL) 
    {
      /* New mission 3: syscall, close all opened files. */
      syscall_close_all_auxi();

      /* Close its child lists. */
      while(!list_empty(&cur->children))
      {
        list_pop_front(&cur->children);
      }

      /* New mission 4: dennying writes to executables */
      if (cur->self_file != NULL)
      {
        // Here we cancell the deny_write of executables.
        file_allow_write(cur->self_file);
        // Close itself.
        file_close(cur->self_file);
      }

      /* New mission 1: output termination messages. */
      // printf ("%s: exit(%d)\n", cur->name, cur->ret);

      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;

        // TODO: Argument passing, this line is a skeleton, should be changed later.
        //*esp = PHYS_BASE - 12;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


/* ----------------- Our new code start at here ----------------- */

/* For mission 2: argument passing */

/* This function extract the file name from the input string file_string, the 
  output is store at name */
static void 
extract_name(char *file_string, char *name, char *save_ptr)
{
  // Ref lib/string.c strtok_r() function.
  name = strtok_r(file_string, ARGS_DELIMITER, &save_ptr);
  // FIXME: When and where release memory ?
}

/* This function extract the args from the file_string, the argv stores the tokenize
  args, and argc stores the number of args, the return value stored in argv, argc */
static void 
extract_args(char *file_string, char *argv[], int *argc)
{
  // Ref lib/string.c strtok_r() function comments.
  char *save_ptr, *token;
  *argc = 1;
  // Extract file name here.
  argv[0] = strtok_r(file_string, ARGS_DELIMITER, &save_ptr);
  // Extract other arguments here.
  while (token = strtok_r(NULL, ARGS_DELIMITER, &save_ptr))
  {
    argv[(*argc)] = token;
    (*argc)++;
  }
}

/* This function put the arguments, which extracted from the extract_args function, into 
  the user stack by the 80x86 convention, see 3.5 in pintos manual, the esp is the user stack
  pointer, by manipulating this pointer the args are put into stack. Moreover we align the memory
  to achieve better performance. */
static char*
put_args_to_stack(char *esp, char *argv[],  int argc)
{
  char *arg_ref[argc]; // Store the reference of arguments

  // Push the arguments string in reverse order, though this order can be arbitary. 
  int i = 0;
  for (i = 0; i < argc; i++)
  {
    esp = esp - (strlen(argv[i])+1);
    strlcpy(esp, argv[i], strlen(argv[i])+1);
    arg_ref[i] =  esp;
  }
  
  // Memory alignment:
  while((int)esp%4)
    esp--;
  
  int *p = (int *)esp;
  p--;
  *p = 0;
  for (i = argc-1;i>=0;i--)
  {
    p--;
    *p = (int *)arg_ref[i];
  }
  p--;
  *p = p+1;
  p--;
  *p = argc;
  p--;
  *p = 0;
  return p;
}



/* For mission 3: system call */
/* This sub-part is for inter process communication, we abstract this as a reader and
  writer problem. Two types of inter process communication are used in this part.
  * The first type: EXEC, the mother thread needs to know if its child starts normally, 
  thus the child need to return its pid to its mother, it is mainly used in exec syscall.
  * The second type: WAIT, this is used as a synchronization tool between multithreads. 
  Specifically, sometimes the mother threads may need to wait its child so as to do other
  works, it is mainly used in wait syscall.  */

/* The reader is usually a mother thread, since it needs the return status, pid of the 
  children thread. The writer is usually a child thread, it writes its status to list.  
  Important: read from empty list will cause block, until someone writes something. */


/* Init inter process comminication lists */
void
init_ipc(void)
{
  list_init(&read_exec_list);
  list_init(&write_exec_list);
  list_init(&read_wait_list);
  list_init(&write_wait_list);
}


/* Auxiliary function of read_ipc and write_ipc since they both need to traverse the writer list 
  or reader list. Here we combine them, where mode == READ represent reader mode, and mode == WRITE
  represent the write mode. */
static void
traverse_ipc(struct list *wr, struct list *re, writer *w, reader *r, int *stat, int mode)
{
  // mode 1 is for read_ipc, mode 0 is for write_ipc.
  struct list *ls = mode ? wr : re;
  struct list_elem *e;
  // Traverse list.
  for (e = list_begin(ls); e != list_end(ls); e = list_next(e))
  {
    // If at reader mode.
    if (mode)
    {
      writer *w_t = list_entry(e, writer, elem);
      // If we find a match.
      if (r->pid_t == w_t->pid_t)
      {
        // Remember to free memory.
        list_remove(&r->elem);
        list_remove(e);
        *stat = w_t->stat;
        free(r);
        free(w);
      }
    } else
    {
      // If at writer mode.
      reader *r_t = list_entry(e, reader, elem);
      if (w->pid_t == r_t->pid_t)
        sema_up(&r_t->sema);
    }
  }
}


/* This function read the child's status according to pid_t, return thr corresponding
  status or pid. The mode controls whether it is a EXEC or a WAIT type. Under the EXEC
  the child's pid is returned, whereas under WAIT the child's exit value is returned. */
static int 
read_ipc(int mode, int pid_t)
{
  // See whether there exists what we want.
  struct list_elem *e;
  int stat_t = 0;
  // Select lists according to ipc types, mode = 1: EXEC, 0: WAIT.
  struct list *w_list = mode ? &write_exec_list : &write_wait_list;
  for (e = list_begin(w_list); e != list_end(w_list); e = list_next(e))
  {
    writer *wr = list_entry(e, writer, elem);
    // If find a match, remove it, return stat.
    if (wr->pid_t == pid_t)
    {
      stat_t = wr->stat;
      list_remove(e);
      free(wr);
      return stat_t;
    }
  }
  // If it don't match any writers, need to block itself to wait.
  reader *re = malloc(sizeof(reader));
  re->pid_t = pid_t;
  struct list *r_list = mode ? &read_exec_list : &read_wait_list;
  list_push_back(r_list, &re->elem);
  // Here semaphore is initialized as 0 for synchronization purpose.
  sema_init(&re->sema, 0);
  sema_down(&re->sema);

  // After someting written to writer list, traverse writer list again.
  w_list = mode ? &write_exec_list : &write_wait_list;
  traverse_ipc(w_list, NULL, NULL, re, &stat_t, READ);
  return stat_t;
}

/* This function writes the status or pid_t to writer list according to given
  pid_t, the mode control whether it is a EXEC or a WAIT type. Under the EXEC 
  the pid of child is saved to stat, whereas under WAIT the exit value status
  is saved to stat */
static void
write_ipc(int mode, int pid_t, int stat_t)
{
  int stub = 0;
  // Push the new writer to writer list so that reader can read from it.
  writer *wr = malloc(sizeof(writer));
  wr->pid_t = pid_t;
  wr->stat = stat_t;
  struct list* w_list = mode ? &write_exec_list : &write_wait_list;
  list_push_back(w_list, &wr->elem);

  // Check if there is reader waiting for this writer.
  struct list *r_list = mode ? &read_exec_list : &read_wait_list;
  traverse_ipc(NULL, r_list, wr, NULL, &stub, WRITE);
}