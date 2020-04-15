#include <bitmap.h>
#include "devices/block.h"
#include "vm/swap.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

#define SECTORS_PER_PAGE  (PGSIZE / BLOCK_SECTOR_SIZE)
struct block *swap_block;
struct bitmap *swap_bitmap;
struct lock st_lock;
/* Init the swap table */
void
vm_st_init (void)
{
    swap_block = block_get_role(BLOCK_SWAP);
    if (swap_block == NULL)
    {
        return ;
    }
    //Creates a bitmap to record whether a swap slot is free.
    swap_bitmap = bitmap_create (block_size (swap_block)/ SECTORS_PER_PAGE );
    bitmap_set_all(swap_bitmap, true);
    lock_init(&st_lock);
}

/*  Swap out: When out of free frames, evict a page from its frame and
    put a copy of into swap disk to get a free frame*/
size_t 
vm_swap_out (void *frame_page)
{

    //Finds a swap slot that a free and flips it to not free.
    size_t swap_free_index = bitmap_scan_and_flip (swap_bitmap, 0, 1, true);
    //Swap is full, panic the kernel.
    if (swap_free_index == BITMAP_ERROR)
    {
        PANIC("Swap is full!");
    }
    //Writes the data in frame_page to a free slot.
    for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
    { 
        block_write(swap_block, swap_free_index * SECTORS_PER_PAGE + i, frame_page + i * BLOCK_SECTOR_SIZE);
    }
    return swap_free_index;
}

/*  Swap in: When page fault handler finds a page is not memory but in
    swap disk, allocate a new frame and move it to memory*/
void 
vm_swap_in (size_t swap_index, void* frame_page)
{
    
    //Writes the data in swap slot whose index is swap_index to the frame_page.
    for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
    {
        block_read(swap_block, swap_index * SECTORS_PER_PAGE + i,frame_page + i * BLOCK_SECTOR_SIZE);
    }
    //Marks the swap slot whose index is swap_index free.
    bitmap_flip(swap_bitmap, swap_index);
}


/* Swap table free, free one table entry given the swap index */
void
vm_swap_free(size_t swap_ind)
{
    if (bitmap_test(swap_bitmap, swap_ind)==false)
    {
        bitmap_set(swap_bitmap, swap_ind, true);    // Set it free
    } else
    {
        PANIC ("Invalid swap index");
    }   
}