#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "lib/kernel/list.h"
/* Number of level 1 indirect links */
#define LEVEL_1 2
/* Number of level 2 indirect links */
#define LEVEL_2 1
/* Number of direct link to block sector number */
#define LEVEL_0 128 - LEVEL_1 - LEVEL_2 - 3
/* Number of indirect link to block sector number: support up to level 2 link */
#define INDIRECT_LINK 128

struct bitmap;
struct inode_disk
  {
    block_sector_t level_zero[LEVEL_0];  /* Number of direct links */
    block_sector_t level_one[LEVEL_1];   /* Number of single indirect links */
    block_sector_t level_two[LEVEL_2];   /* Number of doubly indirect links */
    
    bool is_directory;                   /* An inode directory indicator */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
  };
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct dir* parent_dir;         
    struct inode_disk data;             /* Inode content. */
  };


void inode_init (void);
bool inode_create (block_sector_t, off_t,bool is_directory);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);

#endif /* filesys/inode.h */
