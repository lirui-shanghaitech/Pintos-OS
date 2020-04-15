#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/thread.h"
/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);
struct dir* get_directory_from_path_and_open(const char *);
char* get_filename_from_path(const char *);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();
  bc_init();
  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  bc_done();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_directory) 
{
  block_sector_t inode_sector = 0;
  //get directory from path 
  
  char *filename = get_filename_from_path(name);
  struct dir *dir = get_directory_from_path_and_open(name);
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  //add information is_dirty
                  && inode_create (inode_sector, initial_size, is_directory)
                  // update name
                  && dir_add (dir, filename, inode_sector));
  if (success && is_directory)
  {
    struct inode* ino = inode_open(inode_sector);
    ino->parent_dir = dir;
  }
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);
  free(filename);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct dir *dir = get_directory_from_path_and_open(name);
  // get file name from path 
  
  char *filename = get_filename_from_path(name);
  struct inode *inode = NULL;

  if (dir == NULL) return NULL;
  if (dir != NULL && strlen(filename) > 0 && *filename != '.')
  {
    if(!dir_lookup (dir, filename, &inode))
    dir_close (dir);
  }
  else
  {
    inode = dir -> inode;
  }

  if (inode == NULL || inode->removed )
    return NULL;
  free(filename);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir = get_directory_from_path_and_open(name);
  // get file name from pat
  char *filename = get_filename_from_path(name);
  bool success = dir != NULL && dir_remove (dir, filename);
  dir_close (dir); 
  free(filename);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

char *
get_filename_from_path(const char *path)
{
  char *s = (char*) malloc(sizeof(char) * (strlen(path) + 1));
  memcpy(s, path, strlen(path) + 1);

  char *token, *save_ptr, *last_token = "";
  for (token = strtok_r(s, "/", &save_ptr); token != NULL;
       token = strtok_r(NULL, "/", &save_ptr))
  {
    last_token = token;
  }

  char *filename = malloc(strlen(last_token) + 1);
  memcpy(filename, last_token, strlen(last_token) + 1);
  free (s);

  return filename;
}

struct dir* 
get_directory_from_path_and_open(const char *path)
{
  char *s = (char*) malloc(sizeof(char) * (strlen(path) + 1));
  memcpy(s, path, strlen(path) + 1);
  struct dir* dir;
  if (s[0] == '/' || thread_current()->cwd == NULL)
    {
      dir = dir_open_root();
    }
  else
    {
      dir = dir_reopen(thread_current()->cwd);
    }
  struct dir *next = dir;
  char *token, *save_ptr,*last_token = "";
  for (token = strtok_r(s, "/", &save_ptr); token != NULL;
       token = strtok_r (NULL, "/", &save_ptr))
  {
    struct inode *inode = NULL;
    if (strcmp(token, ".") == 0)
    {
      inode = inode_reopen (dir->inode);
      dir = dir_open(inode);
      continue;
    }
    else if (strcmp(last_token, "..") == 0)
    {
      inode = inode_open (dir -> inode ->parent_dir->inode->sector);
      dir = dir_open(inode);
      continue;
    } 
    if (strlen(last_token) > 0 )
    {
      if (dir_lookup(dir, last_token, &inode))
      {
        
        next = dir_open(inode);
        if(next == NULL) 
        {
          dir_close(dir);
          free (s);
          return NULL;
          
        }
        else
        {
          dir_close(dir);
        }
      }
      else
      {
        inode_close(inode);
        free (s);
        return NULL;
      }
    }
    last_token = token;
    dir = next;
    
  }

    if (dir->inode->removed)
    {
      dir_close(dir);
      free (s);
      return NULL;
    } 
  free (s);
  return dir;
}

