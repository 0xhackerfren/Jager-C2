#ifndef JAGER_BOF_LOADER_H
#define JAGER_BOF_LOADER_H

#include <windows.h>

// COFF file header structures
#pragma pack(push, 1)

typedef struct {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} COFF_FILE_HEADER;

typedef struct {
    char  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} COFF_SECTION;

typedef struct {
    union {
        char  ShortName[8];
        struct {
            DWORD Zeros;
            DWORD Offset;
        } LongName;
    } Name;
    DWORD Value;
    SHORT SectionNumber;
    WORD  Type;
    BYTE  StorageClass;
    BYTE  NumberOfAuxSymbols;
} COFF_SYMBOL;

typedef struct {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD  Type;
} COFF_RELOCATION;

#pragma pack(pop)

// COFF relocation types (x64)
#define IMAGE_REL_AMD64_ADDR64   0x0001
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32    0x0004
#define IMAGE_REL_AMD64_REL32_1  0x0005
#define IMAGE_REL_AMD64_REL32_2  0x0006
#define IMAGE_REL_AMD64_REL32_3  0x0007
#define IMAGE_REL_AMD64_REL32_4  0x0008
#define IMAGE_REL_AMD64_REL32_5  0x0009

// Symbol storage classes
#define IMAGE_SYM_CLASS_EXTERNAL 2
#define IMAGE_SYM_CLASS_STATIC   3

// Beacon data format (for BeaconDataParse)
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

// Beacon format buffer (for BeaconFormatAlloc)
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

// Beacon output buffer
#define BEACON_OUTPUT_SIZE (1024 * 512)

// BOF execution result
typedef struct {
    BYTE  *output;
    DWORD  output_size;
    int    exit_code;
} BOF_RESULT;

// BOF loader API
BOOL bof_load_and_execute(BYTE *coff_data, DWORD coff_size, BYTE *args, DWORD args_size, BOF_RESULT *result);
void bof_result_free(BOF_RESULT *result);

// --- Beacon API functions (exported to BOFs) ---

// Output
void BeaconPrintf(int type, char *fmt, ...);
void BeaconOutput(int type, char *data, int len);

// Data parsing
void BeaconDataParse(datap *parser, char *buffer, int size);
char *BeaconDataPtr(datap *parser, int size);
int BeaconDataInt(datap *parser);
short BeaconDataShort(datap *parser);
int BeaconDataLength(datap *parser);
char *BeaconDataExtract(datap *parser, int *size);

// Format buffer
void BeaconFormatAlloc(formatp *format, int maxsz);
void BeaconFormatReset(formatp *format);
void BeaconFormatFree(formatp *format);
void BeaconFormatAppend(formatp *format, char *text, int len);
void BeaconFormatPrintf(formatp *format, char *fmt, ...);
char *BeaconFormatToString(formatp *format, int *size);
void BeaconFormatInt(formatp *format, int value);

// Token/process
BOOL BeaconUseToken(HANDLE token);
void BeaconRevertToken(void);
BOOL BeaconIsAdmin(void);
void BeaconGetSpawnTo(BOOL x86, char *buffer, int length);

// Utility
BOOL toWideChar(char *src, wchar_t *dst, int max);

// Output type constants
#define CALLBACK_OUTPUT      0
#define CALLBACK_OUTPUT_OEM  30
#define CALLBACK_ERROR       13
#define CALLBACK_OUTPUT_UTF8 31

#endif // JAGER_BOF_LOADER_H
