#ifndef JAGER_LINUX_BASE64_H
#define JAGER_LINUX_BASE64_H

#include "config.h"

DWORD b64_encode(const BYTE *in, DWORD in_len, char *out, DWORD out_cap);
DWORD b64_decode(const char *in, DWORD in_len, BYTE *out, DWORD out_cap);

#endif
