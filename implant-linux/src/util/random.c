/**
 * Cryptographically secure random bytes for Linux implant
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>
#include "../../include/random.h"

int secure_random_bytes(void *buf, size_t len) {
    if (!buf || len == 0) return -1;

    ssize_t ret = getrandom(buf, len, 0);
    if (ret == (ssize_t)len) return 0;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ret = read(fd, buf, len);
    close(fd);
    return (ret == (ssize_t)len) ? 0 : -1;
}

int secure_random_int(int min, int max) {
    if (min >= max) return min;

    unsigned int val = 0;
    if (secure_random_bytes(&val, sizeof(val)) != 0)
        return min;

    return min + (int)(val % (unsigned int)(max - min + 1));
}
