#ifndef VM_SWAP_H
#define VM_SWAP_H

/* Define some public function to manipulate swap table */
void vm_st_init(void);
size_t vm_swap_out (void *frame_page);
void vm_swap_in (size_t swap_index, void* frame_page);
void vm_swap_free(size_t );
#endif