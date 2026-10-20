#ifndef JAGER_LINUX_FS_H
#define JAGER_LINUX_FS_H

#include <stddef.h>
#include <sys/types.h>

int fs_list_dir(const char *path, char *out, int max_out);
int fs_read_file(const char *path, char **out, size_t *out_len);
int fs_write_file(const char *path, const void *data, size_t len);
int fs_delete_file(const char *path);
int fs_mkdir_recursive(const char *path, mode_t mode);
int fs_copy_file(const char *src, const char *dst);
int fs_move_file(const char *src, const char *dst);

#endif /* JAGER_LINUX_FS_H */
