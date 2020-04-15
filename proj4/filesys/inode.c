#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44


/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. Three level of links are implement
   ,zero level: direct link, level one: single indirect link, level two: doubly indirect link */


/* An array to store indirect sector numbers */
typedef struct inode_disk_indirect 
{
  block_sector_t indirect_block[INDIRECT_LINK];
} inode_disk_indirect;

/* Claim of new defined functions */
static block_sector_t level_zero_to_secnum(struct inode_disk *i_disk, off_t ind);
static block_sector_t level_one_to_secnum(struct inode_disk *i_disk, off_t ind, off_t i);
static block_sector_t level_two_to_secnum(struct inode_disk *i_disk, off_t ind, off_t i);
static block_sector_t byte_to_secnum(struct inode_disk *i_disk, off_t pos);

static bool level_zero_allocate(struct inode_disk* i_disk, block_sector_t sec_num);
static bool level_one_allocate(struct inode_disk* i_disk, block_sector_t sec_num, off_t i);
static bool level_two_allocate(struct inode_disk* i_disk, block_sector_t sec_num, off_t i);
static bool inode_allocate(struct inode_disk* i_disk, off_t len);

static void level_zero_deallocate(struct inode_disk* i_disk, off_t sec_num);
static void level_one_deallocate(struct inode_disk* i_disk, block_sector_t sec_num, off_t i);
static void level_two_deallocate(struct inode_disk* i_disk, block_sector_t sec_num, off_t i);
static bool inode_deallocate(struct inode* ind);
/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */


/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length && pos >= 0)
    return byte_to_secnum(&inode->data, pos);
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length,bool is_directory)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);
  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_directory = is_directory;
      if (inode_allocate (disk_inode, disk_inode->length)) 
        {
          bc_write (sector, disk_inode);
          if (sectors > 0) 
            {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) 
                bc_write (sector, disk_inode);
            }
          success = true; 
        } 
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL){
    return NULL;
  }
  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  bc_read (inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          // free_map_release (inode->data.start,
          //                   bytes_to_sectors (inode->data.length));
          inode_deallocate(&inode->data);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          bc_read (sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          bc_read (sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  // File extension, when beyond the EOF, extent the file
  if (byte_to_sector(inode, offset+size-1) == -1u)
  {
    if (!inode_allocate(&inode->data, offset+size))
      return 0;
    inode->data.length = offset + size;
    bc_write(inode->sector, &inode->data);
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          bc_write (sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            bc_read (sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          bc_write (sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

/* ----Our inode implementation functions are all defined here---- */

static off_t
min(off_t a, off_t b)
{
  return a < b ? a: b;
}

/* Transform the offset bytes to the sector number */
static block_sector_t
byte_to_secnum(struct inode_disk *i_disk, off_t pos)
{
  // Change the pos(/byte) to index(/512bytes)
  off_t ind = pos/BLOCK_SECTOR_SIZE;
  // For direct link: level zero
  if (ind < LEVEL_0) 
    return level_zero_to_secnum(i_disk, ind);

  // For single indirect link: level one
  for (off_t i = 0; i < LEVEL_1; i++)
  {
    if (ind < (LEVEL_0 + (i + 1)*INDIRECT_LINK))
      return level_one_to_secnum(i_disk, ind, i);
  }

  // For doubly indirect link: level two
  for (off_t i = 0; i < LEVEL_2; i++)
  {
    if (ind < (LEVEL_0 + LEVEL_1*INDIRECT_LINK + (i + 1)*INDIRECT_LINK*INDIRECT_LINK))
      return level_two_to_secnum(i_disk, ind, i);
  }

  // The file size is too large, currently it don't support
  return -1; 
}

/* Direct link, return the block sector number */
static block_sector_t
level_zero_to_secnum(struct inode_disk *i_disk, off_t ind)
{
    return i_disk->level_zero[ind];
}

/* Single indirect link, return the block sector number */
static block_sector_t
level_one_to_secnum(struct inode_disk *i_disk, off_t ind, off_t i)
{
  inode_disk_indirect* ii_disk = calloc(1, sizeof(inode_disk_indirect));
  // Read the single indirect indoe into cache
  bc_read(i_disk->level_one[i], ii_disk);
  off_t base = LEVEL_0 + i*INDIRECT_LINK;
  block_sector_t ret = ii_disk->indirect_block[ind - base];
  free(ii_disk);

  return ret;
}

/* Doubly indirect link, return the block sector number */
static block_sector_t
level_two_to_secnum(struct inode_disk *i_disk, off_t ind, off_t i)
{
  off_t base = LEVEL_0 + LEVEL_1*INDIRECT_LINK + i*INDIRECT_LINK*INDIRECT_LINK;
  off_t level1 = (ind - base)/ INDIRECT_LINK;
  off_t level2 = (ind - base)% INDIRECT_LINK;

  // Read the two indirect inode into buffer cache
  inode_disk_indirect* ii_disk1 = calloc(1, sizeof(inode_disk_indirect));
  inode_disk_indirect* ii_disk2 = calloc(1, sizeof(inode_disk_indirect));
  bc_read(i_disk->level_two[i], ii_disk1);
  bc_read(ii_disk1->indirect_block[level1], ii_disk2);
  block_sector_t ret = ii_disk2->indirect_block[level2];
  
  // Free memeory
  free(ii_disk1);
  free(ii_disk2);
  return ret;
}


/* Allocate the sector, given the lenght */
static bool
inode_allocate(struct inode_disk* i_disk, off_t len)
{
  off_t sec_num =bytes_to_sectors(len);
  off_t temp = 0;

  // For direct link: level zero
  temp = min(sec_num, LEVEL_0);
  if (level_zero_allocate(i_disk, temp))
    sec_num = sec_num - temp;
  else  
    return false;
  if (sec_num == 0) return true;

  // For single indirect link: level one
  for (off_t m = 0; m < LEVEL_1; m++)
  {
    temp = min(sec_num, INDIRECT_LINK);
    if (level_one_allocate(i_disk, temp, m))
      sec_num = sec_num - temp;
    else  
      return false;
    if (sec_num == 0) return true;
  }

  // For doubly indirect link: level two
  for (off_t m = 0; m < LEVEL_2; m++)
  {
    temp = min(sec_num, INDIRECT_LINK*INDIRECT_LINK);
    if (level_two_allocate(i_disk, temp, m))
      sec_num = sec_num - temp;
    else  
      return false;
    if (sec_num == 0) return true;
  }
}


/* Direct link: level zero, allocate sectors in direct link zone */
static bool
level_zero_allocate(struct inode_disk* i_disk, block_sector_t sec_num)
{
  static char zeros[BLOCK_SECTOR_SIZE] = {0};
  for (off_t i = 0; i < sec_num; i++)
  {
    // If it not been allocated, allocate it
    if (i_disk->level_zero[i] == 0)
    {
      if (free_map_allocate(1, &i_disk->level_zero[i]))
        bc_write(i_disk->level_zero[i], zeros);
      else
        return false;
    }
  }
  // Successfully allocating all direct link sectors
  return true;
}

/* Single indirect link: level one, allocte sectors in single indirect zone */
static bool
level_one_allocate(struct inode_disk* i_disk, block_sector_t sec_num, off_t i)
{
  static char zeros[BLOCK_SECTOR_SIZE] = {0};
  if (i_disk->level_one[i] == 0)
  {
    // First allocate the indirect inode, and write zero to it
    if (free_map_allocate(1, &i_disk->level_one[i]))
      bc_write(i_disk->level_one[i], zeros);
    else
      return false;
  }
  // Then allocate the direct inodes
  inode_disk_indirect* ii_disk = calloc(1, sizeof(inode_disk_indirect));
  off_t cnt = 0;
  bc_read(i_disk->level_one[i], ii_disk);
  for (off_t j = 0; j < INDIRECT_LINK; j++)
  {
    if (cnt < sec_num) {
      if (ii_disk->indirect_block[j] == 0)
      {
        if (free_map_allocate(1, &ii_disk->indirect_block[j]))
          bc_write(ii_disk->indirect_block[j], zeros);
        else
          return false;
      }
    } else
      break;
    cnt++;
  }
  // Write the allocated inode back to disk
  bc_write(i_disk->level_one[i], ii_disk);
  free(ii_disk);
  return true;

}

/* Doubly indirect link: level two, allocate sectors in doubly indirect zone */
static bool
level_two_allocate(struct inode_disk* i_disk, block_sector_t sec_num, off_t i)
{
  static char zeros[BLOCK_SECTOR_SIZE] = {0};
  // First allocate the indirect inode, and write zero to it
  if (i_disk->level_two[i] == 0)
  {
    if ((free_map_allocate(1, &i_disk->level_two[i])))
      bc_write(i_disk->level_two[i], zeros);
    else  
      return false;
  }

  inode_disk_indirect* ii_disk1 = calloc(1, sizeof(inode_disk_indirect));
  inode_disk_indirect* ii_disk2 = calloc(1, sizeof(inode_disk_indirect));
  bc_read(i_disk->level_two[i], ii_disk1);

  off_t cnt = 0;
  for (off_t l1 = 0; l1 < INDIRECT_LINK; l1 ++)
  {
    // If we have not allocated it, allocate 
    if (ii_disk1->indirect_block[l1] == 0)
    {
      if (cnt < sec_num)
      {
        if (free_map_allocate(1, &ii_disk1->indirect_block[l1]))
        {
          bc_write(ii_disk1->indirect_block[l1], zeros);
          for (off_t m = 0 ; m < INDIRECT_LINK; m++)
          {
            if (cnt < sec_num) {
              if (free_map_allocate(1, &ii_disk2->indirect_block[m]))
              {
                bc_write(ii_disk2->indirect_block[m], zeros);
              } else
                return false;
            } else { 
              break;
            }
            cnt++;
          }
          bc_write(ii_disk1->indirect_block[l1], ii_disk2);
          memset(ii_disk2, 0, BLOCK_SECTOR_SIZE);
        } else   
          return false;
      } else
        break;
    } else
    {
      // If we already allocate it, read it from disk to memory
      bc_read(ii_disk1->indirect_block[l1], ii_disk2);
      for (off_t m = 0; m < INDIRECT_LINK; m++)
      {
        if (ii_disk2->indirect_block[m] == 0)
        {
          if (cnt < sec_num)
          {
            if (free_map_allocate(1, &ii_disk2->indirect_block[m]))
            {
              bc_write(ii_disk2->indirect_block[m], zeros);
            } else
              return false;
          } else
          {
            break;
          }
        }
        cnt++;
      }
      bc_write(ii_disk1->indirect_block[l1], ii_disk2);
      memset(ii_disk2, 0, BLOCK_SECTOR_SIZE);
    }
  }
  // Write it back to disk, free the memory
  bc_write(i_disk->level_two[i], ii_disk1);
  free(ii_disk1);
  free(ii_disk2);
  return true;
}


/* Deallocate the inode structure */
static bool 
inode_deallocate(struct inode* ind)
{
  struct inode_disk* i_disk = &ind->data;
  off_t flen = i_disk->length;
  off_t sec_num = bytes_to_sectors(flen);
  off_t temp = 0;
  temp = min(sec_num, LEVEL_0);
  level_zero_deallocate(i_disk, temp);
  sec_num = sec_num - temp;
  if (sec_num == 0) return true;
  for (off_t m = 0; m < LEVEL_1; m++)
  {
    temp = min(sec_num, INDIRECT_LINK);
    level_one_deallocate(i_disk, temp, m);
    sec_num = sec_num - temp;
    if (sec_num == 0) return true;
  }

  for (off_t m = 0; m < LEVEL_2; m++)
  {
    temp = min(sec_num, INDIRECT_LINK*INDIRECT_LINK);
    level_two_deallocate(i_disk, temp, m);
    sec_num = sec_num - temp;
    if (sec_num == 0) return true;
  }
  return false;
}

/* Direct link: level zero, deallocate all inodes corresponding the file */
static void 
level_zero_deallocate(struct inode_disk* i_disk, off_t sec_num)
{
  for (off_t i = 0; i < sec_num; i++)
  {
    free_map_release(i_disk->level_zero[i], 1);
  }
}

/* Single link: level one, deallocate all indirect inodes corresponding a file */
static void
level_one_deallocate(struct inode_disk* i_disk, block_sector_t sec_num, off_t i)
{
  // Read the single indirect inode into the memory
  inode_disk_indirect* ii_disk = calloc(1, sizeof(inode_disk_indirect));
  bc_read(i_disk->level_one[i], ii_disk);
  for (off_t j = 0; j < sec_num; j++)
  {
    free_map_release(ii_disk->indirect_block[j], 1);
  }
  // Finally, free the father indirect inodes
  free_map_release(i_disk->level_one[i], 1);
  free(ii_disk);
}

/* Doubly link: level two, deallocate all indirect inodes corresponding a file */
static void
level_two_deallocate(struct inode_disk* i_disk, block_sector_t sec_num, off_t i)
{
  // Read the doubly indirect inode into memory
  inode_disk_indirect* ii_disk1 = calloc(1, sizeof(inode_disk_indirect));
  inode_disk_indirect* ii_disk2 = calloc(1, sizeof(inode_disk_indirect));
  bc_read(i_disk->level_two[i], ii_disk1);

  off_t level1 = sec_num/INDIRECT_LINK;
  off_t level2 = sec_num%INDIRECT_LINK;

  // Deallocate the inodes
  for (off_t m = 0; m < level1; m++)
  {
    bc_read(ii_disk1->indirect_block[m], ii_disk2);
    for (off_t n = 0; n < level2; n++)
    {
      free_map_release(ii_disk2->indirect_block[n], 1);
    }
  }
  // Reset the ii_disk2 to all zeros
  memset(ii_disk2, 0, BLOCK_SECTOR_SIZE);
  for (off_t n = 0; n < level2; n++)
  {
    bc_read(ii_disk1->indirect_block[level1], ii_disk2);
    free_map_release(ii_disk2->indirect_block[n], 1);
  }
  // Finally, free the fathe indirect inodes
  free_map_release(i_disk->level_two[i], 1);
  // Free the memory
  free(ii_disk1);
  free(ii_disk2);
}