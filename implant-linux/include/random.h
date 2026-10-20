#ifndef JAGER_LINUX_RANDOM_H
#define JAGER_LINUX_RANDOM_H

#include <stddef.h>

int secure_random_bytes(void *buf, size_t len);
int secure_random_int(int min, int max);

#endif
