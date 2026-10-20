#ifndef JAGER_PIVOT_H
#define JAGER_PIVOT_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- SOCKS5 Proxy (socks.c) ---
BOOL socks_start(WORD port);
BOOL socks_stop(void);
int  socks_get_active_count(void);
WORD socks_get_port(void);

// --- Port Forwarding (portfwd.c) ---
// Returns forward ID (>0) on success, -1 on failure
int  portfwd_add(const char* bind_host, int bind_port,
                 const char* fwd_host, int fwd_port);
int  portfwd_remove(int fwd_id);
int  portfwd_list(char* output, int output_sz);
int  portfwd_get_active_count(void);

// --- Reverse Port Forward (not yet implemented) ---
BOOL rportfwd_add(WORD remote_port, const char* local_host, WORD local_port);
BOOL rportfwd_remove(WORD remote_port);

// --- Named Pipe P2P (pipe.c) ---
BOOL p2p_listen(const char* pipe_name);
BOOL p2p_connect(const char* target_host, const char* pipe_name);
int  p2p_get_active_count(void);

// --- TCP P2P (tcp_pivot.c) ---
BOOL tcp_pivot_listen(WORD port);
BOOL tcp_pivot_connect(const char* host, WORD port);

#ifdef __cplusplus
}
#endif

#endif // JAGER_PIVOT_H
