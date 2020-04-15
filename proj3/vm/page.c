#include <stdio.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

#include "userprog/pagedir.h"
#include "lib/kernel/list.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "filesys/file.h"

/* Define supplementabl page table as a link list, note that, unlike frame table. 
   The supplemental page table is per-process thus a global lock is needless */ 
supp_pt_entry* vm_supp_pt_find(struct list* supplemental_table, void* user_page, struct list_elem* e);
static void vm_supp_pt_load_file(supp_pt_entry* supp_entry, void* kernel_page);

/* Delete a supplemental page table */
void
vm_supp_pt_delete(struct list *supplemental_table)
{
    ASSERT(supplemental_table != NULL);

    // Traverse the supplemental page table, delete entries
    while (!list_empty(supplemental_table))
    {
        struct list_elem *e = list_pop_front(supplemental_table);
        supp_pt_entry* spt = list_entry(e, struct supp_pt_entry, elem);
        
        if (spt->kernel_page == NULL)
        {
            if (spt->status == ON_SWAP)
            {
                vm_swap_free(spt->swap_ind);
            }
        } else if (spt->kernel_page != NULL)
        {
            if (spt->status == ON_FRAME)
                vm_ft_fake_free(spt->kernel_page);
        }
        
        free(spt);
    }
}

/* Install a page to supplemental page table, return true if success, 
   flase otherwise. Note that, the page is currently on the frame */
bool
vm_supp_pt_set_page(struct list* supplemental_table, void* user_page, void* kernel_page)
{
    
    supp_pt_entry* supp_entry = (supp_pt_entry*) malloc(sizeof(supp_pt_entry));
    if (supp_entry == NULL)                 // Fail to allocate memory, return false
    {
        free(supp_entry);
        return false;
    }
    supp_entry->swap_ind = -1;              // Not in swap slot, thus need to set to -1
    supp_entry->user_page = user_page;
    supp_entry->kernel_page = kernel_page;
    supp_entry->status = ON_FRAME;          // Note that, page is on frame
    list_push_back(supplemental_table, &supp_entry->elem);
    return true;
}

/* Helper: stack growth @ page fault, set the status of supp entry to ALL_ZEROS
   when call to load_page, all elem of that page will be set to zero */
void 
vm_supp_pt_set_zero(struct list* supplemental_table, void* user_page)
{
    // Allocate entry memory, panic if fail
    supp_pt_entry* supe = (supp_pt_entry*) malloc(sizeof(supp_pt_entry));
    if (supe == NULL)
        PANIC ("Out of memeory !");
    
    // Set the supp entry status: ALL_ZEROS, thus when call load_page, it will be set to zero
    supe->user_page = user_page;
    supe->kernel_page = NULL;
    supe->status = ALL_ZEROS;

    // Insert to supplemental page table
    list_push_back(supplemental_table, &supe->elem);
}

/* Helper: frame allocator, when run out of frames, evict one frame, set the supp entry with
   ON_SWAP status, thus when trap to page fault the load_page will call the swap in */
void
vm_supp_pt_set_swap(struct list* supplemental_table, void* page, size_t swap_ind)
{
    struct list_elem e;
    supp_pt_entry* supe = vm_supp_pt_find(supplemental_table, page, &e);

    // Set the supp entry status: ON_SWAP, thus when call load_page, it will find page in swap slots
    supe->swap_ind = swap_ind;
    supe->status   = ON_SWAP;
    supe->kernel_page = NULL;
    
}

/* Helper: for lazy load file, set the state of supp page table to ON_FILESYS,
   also set other parameters, offset, file, read_bytes... */

void 
vm_supp_pt_set_filesys(struct list* supplemental_table, off_t offset, size_t page_read_bytes,
    size_t page_zero_bytes, void* user_page, struct file* file, bool is_write)
{
    supp_pt_entry* supe = (supp_pt_entry*) malloc(sizeof(supp_pt_entry));
    if (supe == NULL)
        PANIC ("Out of memeory");

    // Set some parameters
    supe->page_read_bytes = page_read_bytes;
    supe->page_zero_bytes = page_zero_bytes;
    supe->is_writable     = is_write;
    supe->status          = ON_FILESYS;
    supe->f_off           = offset;
    supe->file            = file;
    supe->user_page       = user_page;
    supe->kernel_page     = NULL;

    // Insert to supplemental page table
    list_push_back(supplemental_table, &supe->elem);
}



/* Helper of page fault handler, load the page according to the status of page such that,
   status==on_swap, we have to load it from swap slot to frame. */
bool
vm_supp_pt_load_page(struct list* supplemental_table, void* user_page, uint32_t* pagedir)
{
    struct list_elem e;
    bool write_enable = true;
    // Check if there exist supp entry associated with user_page
    supp_pt_entry* supe = vm_supp_pt_find(supplemental_table, user_page, &e);
    if (supe == NULL)
    {
        return false;
    }
    // Allocate frame for required page, return false if fail
    void* fp = vm_ft_get_page(PAL_USER, user_page);
    if (fp ==NULL)
        return false;

    /* Load data from file system, swap or set them to all zeros. Do nothing, \
      if already on frame */
    if (supe->status == ON_FRAME)
    {
        goto done;
    } else if (supe->status == ALL_ZEROS)
    {
        memset (fp, 0, PGSIZE);
        goto done;
    } else if (supe->status == ON_SWAP)
    {
        vm_swap_in(supe->swap_ind, fp);
        goto done;
    } else if (supe->status == ON_FILESYS)
    {
        vm_supp_pt_load_file(supe, fp);
        write_enable = supe->is_writable;
        goto done;
    } else {
        PANIC ("Unkown states !");
    }
        
    // Add a mapping from user page to kernel virtual address kernal page
    done:
    if (pagedir_set_page(pagedir, user_page, fp, write_enable))
    {
        supe->status = ON_FRAME;
        supe->kernel_page = fp;
        pagedir_set_dirty(pagedir, fp, false);
        vm_ft_unpin(fp);
        return true;
    } else 
    {
        vm_ft_true_free(fp);
        return false;
    }
}

/* Helper: find the  supplemental page table entry in supp table, return a pointer
   if find it, NULL if it doesn't exist */
supp_pt_entry*
vm_supp_pt_find(struct list* supplemental_table, void* user_page, struct list_elem* e)
{

    for (e = list_begin(supplemental_table); e != list_end(supplemental_table); e = list_next(e))
    {
        supp_pt_entry *f = list_entry(e, supp_pt_entry, elem);
        if (f->user_page == user_page)
        {
            return f;
        }
    }
    return NULL;
}

/* Helper: load file from filer system page by page */
static void 
vm_supp_pt_load_file(supp_pt_entry* supp_entry, void* kernel_page)
{
    // Read valid bytes from file
    file_seek(supp_entry->file, supp_entry->f_off);
    uint32_t num_read = file_read(supp_entry->file, kernel_page, supp_entry->page_read_bytes);

    // If there still space in one page, write zeros to it
    ASSERT (supp_entry->page_read_bytes + supp_entry->page_zero_bytes == PGSIZE);
    memset(kernel_page+num_read, 0, supp_entry->page_zero_bytes);
}