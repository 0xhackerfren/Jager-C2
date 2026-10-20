#ifndef JAGER_LINUX_TASKS_H
#define JAGER_LINUX_TASKS_H

#include "config.h"
#include "transport.h"

BOOL task_dispatch(PIMPLANT_CONFIG config, PC2_TASK task, PC2_RESULT result);

typedef struct {
    BYTE  *data;
    DWORD  size;
    DWORD  capacity;
} OUTPUT_BUFFER, *POUTPUT_BUFFER;

POUTPUT_BUFFER output_new(DWORD initial_capacity);
BOOL output_write(POUTPUT_BUFFER buf, const BYTE *data, DWORD size);
BOOL output_printf(POUTPUT_BUFFER buf, const char *fmt, ...);
void output_free(POUTPUT_BUFFER buf);

#endif
