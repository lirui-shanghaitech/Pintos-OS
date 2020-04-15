#include <stdio.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

#include "userprog/pagedir.h"
#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

/*  Here we define global frame lock, which gurantee only one 
    thread can manipulate the frame table at a time. */
static struct lock ft_lock;

/* A circular list stores all ft_entries, and a clock pointer */
static struct list frame_table;
static struct list_elem *clk_p;

static ft_entry* vm_ft_find(void *kernel_page, struct list_elem *e);
static ft_entry* vm_ft_pick_frame(uint32_t *pagedir);
static void vm_ft_free_page_fake(void *kernel_page);
static void vm_ft_free_page(void *kernel_page);

/* Init the frame table */
void 
vm_ft_init(void)
{
    list_init(&frame_table);
    lock_init(&ft_lock);
}

/* Allocate a new frame, return the kernel virtual address of that page */
void*
vm_ft_get_page(enum palloc_flags flag, void *user_page)
{
    ASSERT(is_user_vaddr(user_page));
    lock_acquire(&ft_lock);
    void *fp = palloc_get_page(PAL_USER|flag);
    if (fp == NULL)
    {
        
        ft_entry* fe = vm_ft_pick_frame(thread_current()->pagedir);
        if (fe == NULL||fe->th == NULL)
            PANIC("Fail to find a frame to evict");
        
        struct list_elem e;
        supp_pt_entry* supe = vm_supp_pt_find(&fe->th->supplemental_table, fe->user_page, &e);
        supe->is_dirty = supe->is_dirty || pagedir_is_dirty(fe->th->pagedir, fe->user_page);
        // Clear the mapping in page directory, swap out and set supp entry
        pagedir_clear_page(fe->th->pagedir, fe->user_page);
        size_t swap_ind = vm_swap_out(fe->kernel_page);
        vm_supp_pt_set_swap(&fe->th->supplemental_table, fe->user_page, swap_ind);
        // Update frame table and page table
        vm_ft_free_page(fe->kernel_page);
        fp = palloc_get_page(PAL_USER|flag);

        // Delete the origin frame entry
        // free(fe);
    }

    // Update frame table entries.
    ft_entry *frame_entry = malloc(sizeof(ft_entry));
    struct thread *t = thread_current();
    frame_entry->user_page = user_page;
    frame_entry->kernel_page = fp;
    frame_entry->th = t;
    frame_entry->pin = true;    // When first load to frame, can't be swap out

    // Insert new entries to frame table
    list_push_back(&frame_table, &frame_entry->elem);
    lock_release(&ft_lock);

    return fp;
}

/* Free a frame given the kernel virtual address, only called when you have a lock */
static void
vm_ft_free_page(void *kernel_page)
{
    ASSERT(pg_ofs(kernel_page)==0||is_kernel_vaddr(kernel_page));

    // Find the page table entry associated with kernel_page
    struct list_elem e;
    ft_entry *f = vm_ft_find(kernel_page, &e);
    if (f == NULL)
        PANIC("Not a valid page to be freed !");

    // Remove it from frame table
    list_remove(&f->elem);
    palloc_free_page(kernel_page);
}

/* Free a frame given the kernel virtual address, only delete from frame table
   , however, we don't really release this page, only called when you hold a lock */
static void
vm_ft_free_page_fake(void *kernel_page)
{
    ASSERT(pg_ofs(kernel_page)==0||is_kernel_vaddr(kernel_page));

    // Find the page table entry associated with kernel_page
    struct list_elem e;
    ft_entry *f = vm_ft_find(kernel_page, &e);
    if (f == NULL)
        PANIC("Not a valid page to be freed !");

    // Remove it from frame table
    list_remove(&f->elem);
}


/* A wrapper of vm_ft_free_page, with lock hold */
void
vm_ft_true_free(void *kernel_page)
{
    lock_acquire(&ft_lock);
    vm_ft_free_page(kernel_page);
    lock_release(&ft_lock);
}

/* A wrapper of vm_ft_free_fake, with lock hold */
void 
vm_ft_fake_free(void *kernel_page)
{
    lock_acquire(&ft_lock);
    vm_ft_free_page_fake(kernel_page);
    lock_release(&ft_lock);
}

/* Unpin a frame, so that it can be swaped out later */
void
vm_ft_unpin(void* kernel_page)
{
    lock_acquire(&ft_lock);
    struct list_elem e;
    ft_entry* fe = vm_ft_find(kernel_page, &e);
    if (fe == NULL)
    {
        lock_release(&ft_lock);
        PANIC ("Invalid kernel page address");
    }   
    fe->pin = false;
    lock_release(&ft_lock);
}

/* Pin a frame, so that it can't be swaped out later */
void
vm_ft_pin(void* kernel_page)
{
    lock_acquire(&ft_lock);
    struct list_elem e;
    ft_entry* fe = vm_ft_find(kernel_page, &e);
    if (fe == NULL)
        PANIC ("Invalid kernel page address");
    fe->pin = true;
    lock_release(&ft_lock);
}



/* Helper: return ft_entry given kernel virtual address, NULL if not exists */
static ft_entry* 
vm_ft_find(void *kernel_page, struct list_elem *e)
{
    ASSERT(pg_ofs(kernel_page)==0||is_kernel_vaddr(kernel_page));

    for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
    {
        ft_entry *f = list_entry(e, ft_entry, elem);
        if (f->kernel_page == kernel_page)
            return f;
    }
    return NULL;
}

/* Helper:  Pick a frame to swap out. To approximate LRU, a clock algorithm is implemented */
static ft_entry*
vm_ft_pick_frame(uint32_t* pagedir)
{
    // TODO: not implement yet, clock-algorithm
    struct list_elem *e;

    // Implement a clock algorithm, using 2th iteration of frame table
    size_t d_frame_size = 2 * list_size(&frame_table);
    size_t ind = 0;
    for (ind = 0; ind < d_frame_size; ind++)
    {
        // Set the clock pointer to the next element of  list except for the end
        if (clk_p == NULL || clk_p == list_end(&frame_table))
            clk_p = list_begin(&frame_table);
        else 
            clk_p = list_next(&frame_table);
        ft_entry* fe = list_entry(clk_p, ft_entry, elem);

        // Clock algorithm: if already pinned can't evict it
        if (fe->pin == false)
        {
            // If already accessed give it a second chance
            if (pagedir_is_accessed(pagedir, fe->user_page))
            {
                pagedir_set_accessed(pagedir, fe->user_page, false);
                continue;
            }
            return fe;
        } 
    }
    return NULL;
}
