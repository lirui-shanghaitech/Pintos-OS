#ifndef VM_FRAME_H
#define VM_FRAME_H


/* Define the frame table entry. */
typedef struct ft_entry
{
    void *user_page;        // User page address
    void *kernel_page;      // Kernal page address
    struct thread *th;      // Associated thread
    struct list_elem elem;  // List element
    bool pin;               // Used to track is a page is pinned, it pinnned, can't swap out
} ft_entry;

/* Define some public function to manipulate frame table */
void vm_ft_init(void);
void* vm_ft_get_page(enum palloc_flags, void* );
void vm_ft_true_free(void* );
void vm_ft_fake_free(void* );
void vm_ft_unpin(void* );
void vm_ft_pin(void* );
#endif