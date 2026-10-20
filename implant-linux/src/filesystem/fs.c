/**
 * fs.c - File operations for Linux implant
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../../include/fs.h"
#include "../../include/config.h"

#define FS_COPY_BUF_SIZE 65536

int fs_list_dir(const char *path, char *out, int max_out) {
    if (!path || !out || max_out <= 0) return -1;

    DIR *dir = opendir(path);
    if (!dir) return -1;

    int offset = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);

        struct stat st;
        int n;
        if (stat(full, &st) == 0) {
            n = snprintf(out + offset, (size_t)max_out - (size_t)offset,
                         "%c %10ld  %s\n",
                         S_ISDIR(st.st_mode) ? 'd' : '-',
                         (long)st.st_size, ent->d_name);
        } else {
            n = snprintf(out + offset, (size_t)max_out - (size_t)offset,
                         "?              %s\n", ent->d_name);
        }
        if (n > 0 && offset + n < max_out) offset += n;
        else break;
    }

    closedir(dir);
    return 0;
}

int fs_read_file(const char *path, char **out, size_t *out_len) {
    if (!path || !out || !out_len) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long flen = ftell(f);
    if (flen < 0) {
        fclose(f);
        return -1;
    }
    if ((size_t)flen > MAX_OUTPUT_SIZE) {
        fclose(f);
        return -1; /* File too large */
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    char *buf = (char *)malloc((size_t)flen + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }

    size_t nread = fread(buf, 1, (size_t)flen, f);
    fclose(f);
    if (nread != (size_t)flen) {
        free(buf);
        return -1;
    }

    buf[flen] = '\0';
    *out = buf;
    *out_len = (size_t)flen;
    return 0;
}

int fs_write_file(const char *path, const void *data, size_t len) {
    if (!path || !data) return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;

    const unsigned char *p = (const unsigned char *)data;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        p += (size_t)n;
        remaining -= (size_t)n;
    }

    close(fd);
    return (int)len;
}

int fs_delete_file(const char *path) {
    if (!path) return -1;

    struct stat st;
    if (stat(path, &st) != 0) return -1;

    if (S_ISDIR(st.st_mode)) {
        if (rmdir(path) != 0) return -1;
    } else {
        if (unlink(path) != 0) return -1;
    }
    return 0;
}

int fs_mkdir_recursive(const char *path, mode_t mode) {
    if (!path || !*path) return -1;

    char tmp[1024];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    size_t len = strlen(tmp);
    if (len == 0) return -1;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }

    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

int fs_copy_file(const char *src, const char *dst) {
    if (!src || !dst) return -1;

    int in_fd = open(src, O_RDONLY);
    if (in_fd < 0) return -1;

    int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        close(in_fd);
        return -1;
    }

    char buf[FS_COPY_BUF_SIZE];
    int rc = 0;
    while (1) {
        ssize_t n = read(in_fd, buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) {
            rc = -1;
            break;
        }

        const char *p = buf;
        ssize_t remaining = n;
        while (remaining > 0) {
            ssize_t w = write(out_fd, p, (size_t)remaining);
            if (w <= 0) {
                rc = -1;
                remaining = 0;
                break;
            }
            p += w;
            remaining -= w;
        }
        if (rc != 0) break;
    }

    close(in_fd);
    close(out_fd);
    if (rc != 0) {
        unlink(dst);
        return -1;
    }
    return 0;
}

int fs_move_file(const char *src, const char *dst) {
    if (!src || !dst) return -1;
    if (rename(src, dst) == 0) return 0;
    if (fs_copy_file(src, dst) != 0) return -1;
    if (fs_delete_file(src) != 0) {
        unlink(dst);
        return -1;
    }
    return 0;
}
