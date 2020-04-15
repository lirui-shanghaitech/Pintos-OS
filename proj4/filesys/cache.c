#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

/* Buffer cache list: each element is a bc_entry */
static struct list bc_list;
/* A clock pointer for eviction algorithm */
static struct list_elem *cp;      
/* A global buffer cache lock for synchronization */
static struct lock bc_lock;

static bc_entry* bc_pick_entry(void);
static bc_entry* bc_look_up(block_sector_t );

/* Initialize the buffer cache list and lock */
void
bc_init(void)
{
    lock_init(&bc_lock);    // Init buffer cache lock
    list_init(&bc_list);    // Init buffer cache list

    // Init bc entry with dirty, access, in_use flag equal to false
    for (int i = 0; i < BC_SIZE; i++)
    {
        bc_entry* bce = malloc(sizeof(bc_entry));
        bce->in_use = false;
        bce->dirty  = false;
        bce->access = false;
        bce->ind    = i;
        list_push_back(&bc_list, &bce->elem);
    }
}

/* Look up the buffer entry given the block sector number, return a pointer
 * point to buffer entry if find it, return null otherwise */
static bc_entry* 
bc_look_up(block_sector_t sec_num)
{
    struct list_elem* e;
    // Iterate through buffer entry list
    for (e = list_begin(&bc_list); e != list_end(&bc_list); e = list_next(e))
    {
        bc_entry* bce = list_entry(e, bc_entry, elem);
        // Buffer cache hit
        if (bce->in_use == true && bce->d_sector == sec_num)
        {
            return bce;
        }
    }
    // Buffer cache miss
    return NULL;
}

/* Find a buffer cache entry to evict, to approximate LRU, a clock algorithm 
 * is utilized, return the buffer entry pointer if find one, return NULL if
 * no buffer entry can be evicted */
static bc_entry*
bc_pick_entry(void)
{
    struct list_elem* e;

    // Implement a clock algorithm, using 2th iteration of buffer cache lenght
    size_t d_bc_size = 2 * list_size(&bc_list);
    size_t ind = 0;

    for (ind = 0; ind < d_bc_size; ind++)
    {
        // Set the clock pointer to the next element of list except for end
        if (cp == NULL || cp == list_end(&bc_list))
        {
            cp = list_begin(&bc_list);
        } else
        {
            cp = list_next(&bc_list);
        }
        // Extract buffer entry from buffer cache list
        bc_entry* bce = list_entry(cp, bc_entry, elem);

        // Clock algorithm: if find an unused one just return it
        if (bce->in_use == false)
        {
            return bce;
        }

        // If it is accessed recently, give it second chance, else evict it
        if (bce->access)
        {
            bce->access = false;
        } else
        {
            // If it has been modified, need to write back to disk
            if (bce->dirty)
            {
                block_write(fs_device, bce->d_sector, bce->buf);
                bce->dirty = false;
            }
            // If not, just return it
            bce->in_use = false;
            return bce;
        }
        
    }

    // If can't find an entry to evict, retrun NULL
    return NULL;
}

/* Read the content of block sector: sector_num into the memory, if cache hit
 * just read the content of cache into memory, if cache miss, bring the content
 * to cache, then read the cache into memory. */
void
bc_read(block_sector_t sec_num, void* mem)
{
    lock_acquire(&bc_lock);
    bc_entry* bce = bc_look_up(sec_num);

    // When cache hit: just bring the content in cache to memory
    if (bce != NULL)
    {
        bce->access = true;
        memcpy(mem, bce->buf, BLOCK_SECTOR_SIZE);
    }

    // When cache miss: bring the content into the cache, then read from cache
    if (bce == NULL)
    {
        bce = bc_pick_entry();
        bce->d_sector = sec_num;
        bce->dirty    = false;
        bce->in_use   = true;
        // Read from disk to buffer cache
        block_read(fs_device, sec_num, bce->buf);
        // Read from cache to memory
        bce->access = true;
        memcpy(mem, bce->buf, BLOCK_SECTOR_SIZE);
    }

    // Release the global buffer cache lock
    lock_release(&bc_lock);
}

/* Write the content of memory to cache, if cache hit just write the content
 * directly to cache and set the dirty, access bit. When cache miss, first bring
 * them into cache and write the content to cache.  */
void
bc_write(block_sector_t sec_num, void* mem)
{
    lock_acquire(&bc_lock);
    bc_entry* bce = bc_look_up(sec_num);
    // When cache hit: just write the content to cache, also set the access, dirty bits
    if (bce != NULL)
    {
        bce->access = true;
        bce->dirty  = true;
        memcpy(bce->buf, mem, BLOCK_SECTOR_SIZE);
    }
    // When cache miss: bring the sec_num to cache and write to cache
    if (bce == NULL)
    {
        bce = bc_pick_entry();
        bce->d_sector = sec_num;
        bce->dirty    = true;
        bce->in_use   = true;
        bce->access   = true;
        // Read from the disk to cache
        block_read(fs_device, sec_num, bce->buf);
        // Write from the memory to cache
        memcpy(bce->buf, mem, BLOCK_SECTOR_SIZE);
    }

    // Release the global buffer cache lock
    lock_release(&bc_lock);
}


/* Free the buffer cache, write all the content in cache back to disk */
void
bc_done(void)
{
    lock_acquire(&bc_lock);
    struct list_elem* e;
    // Iterate through buffer entry list
    for (e = list_begin(&bc_list); e != list_end(&bc_list); e = list_next(e))
    {
        bc_entry* bce = list_entry(e, bc_entry, elem);
        // Only when it is in use and dirty, we write it back to disk
        if (bce->in_use && bce->dirty)
        {
            block_write(fs_device, bce->d_sector, bce->buf);
            bce->dirty = false;
        }
    }
    lock_release(&bc_lock);
}