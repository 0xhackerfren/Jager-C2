#ifndef JAGER_TRACKED_ALLOC_H
#define JAGER_TRACKED_ALLOC_H

#include <windows.h>

void tracked_alloc_init(void);
void *tracked_alloc(SIZE_T size);
void *tracked_realloc(void *old, SIZE_T new_size);
void tracked_free(void *p);
void tracked_encrypt_all(BYTE *key, int key_len);
void tracked_decrypt_all(BYTE *key, int key_len);

#endif /* JAGER_TRACKED_ALLOC_H */
