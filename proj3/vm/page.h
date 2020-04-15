#ifndef VM_PAGE_H
#define VM_PAGE_H
#include "filesys/off_t.h"

/* The status of specific page */
enum page_status
{
    ALL_ZEROS,      // All zeros frame
    ON_FRAME,       // Pages in memory
    ON_SWAP,        // Pages in swap slot
    ON_FILESYS      // Pages from file system
};

/* Supplemental page table entry */
typedef struct supp_pt_entry
{
    void *user_page;        // Store user virtual address
    void *kernel_page;      // Store kernel virtual address, only valid when page is a frame
    enum page_status status;       // Record the status of page, on frame , all zeros, on swap
    struct list_elem elem;  // SUPPT is a link list
    size_t swap_ind;        // Record the swap index, if page on swap slot

    struct file *file;      // File need to be read
    size_t page_read_bytes; // Number of valid bytes for one page
    size_t page_zero_bytes; // Number of bytes need to be filled with zero
    off_t f_off;            // Offset of file content
    bool  is_writable;      // If it is read only or write-read
    bool is_dirty;          // Whether the entry is writen 
} supp_pt_entry;

/* Define some vm_supp_pt_* functions to manipluate supp page table */

void vm_supp_pt_delete(struct list* );
bool vm_supp_pt_set_page(struct list*, void*, void* );
void vm_supp_pt_set_zero(struct list*, void* );
bool vm_supp_pt_load_page(struct list*, void*, uint32_t* );
supp_pt_entry* vm_supp_pt_find(struct list*, void*, struct list_elem* );
void vm_supp_pt_set_swap(struct list*, void*, size_t );
void vm_supp_pt_set_filesys(struct list*, off_t, size_t, size_t, void*, struct file*, bool );
#endif