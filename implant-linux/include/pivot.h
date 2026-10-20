#ifndef JAGER_LINUX_PIVOT_H
#define JAGER_LINUX_PIVOT_H

#include "config.h"

BOOL socks_start(int port);
BOOL socks_stop(void);
BOOL portfwd_add(int local_port, const char *remote_host, int remote_port, int *out_id);
BOOL portfwd_remove(int fwd_id);
int portfwd_list(char *out, int max_out);
void portfwd_cleanup(void);
BOOL p2p_listen(const char *socket_path);
BOOL p2p_connect(const char *target, const char *socket_path);
BOOL tcp_pivot_listen(int port);
BOOL tcp_pivot_connect(const char *host, int port);
BOOL p2p_relay_configure(const char *json, size_t json_len);
void p2p_cleanup(void);
int tunnel_init(PIMPLANT_CONFIG config);
int tunnel_poll(PIMPLANT_CONFIG config);
void tunnel_cleanup(void);
void pivot_cleanup(void);

#endif
