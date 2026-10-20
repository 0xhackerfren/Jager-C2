#include <windows.h>
#include "../../include/tracked_alloc.h"

typedef struct {
    void *addr;
    SIZE_T size;
    int active;
} TrackedRegion;

#define MAX_TRACKED_REGIONS 512
static TrackedRegion g_tracked[MAX_TRACKED_REGIONS];
static int g_tracked_count = 0;
static CRITICAL_SECTION g_tracked_cs;
static volatile LONG g_tracked_cs_ready = 0;

void tracked_alloc_init(void) {
    if (InterlockedCompareExchange(&g_tracked_cs_ready, 1, 0) == 0)
        InitializeCriticalSection(&g_tracked_cs);
}

void *tracked_alloc(SIZE_T size) {
    void *p;

    tracked_alloc_init();
    p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!p)
        return NULL;

    EnterCriticalSection(&g_tracked_cs);
    for (int i = 0; i < MAX_TRACKED_REGIONS; i++) {
        if (!g_tracked[i].active) {
            g_tracked[i].addr = p;
            g_tracked[i].size = size;
            g_tracked[i].active = 1;
            if (i >= g_tracked_count)
                g_tracked_count = i + 1;
            break;
        }
    }
    LeaveCriticalSection(&g_tracked_cs);
    return p;
}

void *tracked_realloc(void *old, SIZE_T new_size) {
    void *p;

    tracked_alloc_init();
    p = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, old, new_size);
    if (!p)
        return NULL;

    EnterCriticalSection(&g_tracked_cs);
    for (int i = 0; i < g_tracked_count; i++) {
        if (g_tracked[i].active && g_tracked[i].addr == old) {
            g_tracked[i].addr = p;
            g_tracked[i].size = new_size;
            break;
        }
    }
    LeaveCriticalSection(&g_tracked_cs);
    return p;
}

void tracked_free(void *p) {
    if (!p)
        return;

    tracked_alloc_init();
    EnterCriticalSection(&g_tracked_cs);
    for (int i = 0; i < g_tracked_count; i++) {
        if (g_tracked[i].active && g_tracked[i].addr == p) {
            g_tracked[i].active = 0;
            g_tracked[i].addr = NULL;
            g_tracked[i].size = 0;
            break;
        }
    }
    LeaveCriticalSection(&g_tracked_cs);

    HeapFree(GetProcessHeap(), 0, p);
}

void tracked_encrypt_all(BYTE *key, int key_len) {
    if (!key || key_len <= 0)
        return;

    tracked_alloc_init();
    EnterCriticalSection(&g_tracked_cs);
    for (int i = 0; i < g_tracked_count; i++) {
        if (g_tracked[i].active && g_tracked[i].addr) {
            BYTE *p = (BYTE *)g_tracked[i].addr;
            for (SIZE_T j = 0; j < g_tracked[i].size; j++)
                p[j] ^= key[j % (SIZE_T)key_len];
        }
    }
    LeaveCriticalSection(&g_tracked_cs);
}

void tracked_decrypt_all(BYTE *key, int key_len) {
    tracked_encrypt_all(key, key_len);
}
