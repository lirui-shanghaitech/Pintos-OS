#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "lib/kernel/list.h"

#define BC_SIZE 64      // Define the buffer cache size

/* Buffer cache entry */
typedef struct bc_entry {
    block_sector_t d_sector;          // Disk sector number
    uint8_t buf[BLOCK_SECTOR_SIZE];   // Buffer of size BLOCK_SETOR_SIZE
    bool dirty;                       // Dirty bit for eviction algorithm
    bool access;                      // Access bit for eviction algorithm
    bool in_use;                      // Whether the buffer is in use
    uint8_t ind;                      // Index of buffer cache entry range from 0 to 63
    struct list_elem elem;            // Maintain as a link list
} bc_entry;


/* Functions that manipulate buffer cache */
void bc_init(void);
void bc_read(block_sector_t , void* );
void bc_write(block_sector_t , void* );
void bc_done(void);

#endif