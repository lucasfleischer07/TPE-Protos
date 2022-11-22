#ifndef PROTOCOLNIO_H
#define PROTOCOLNIO_H
#include "selector.h"

#define MAX_ADMINS 3
#define ADMIN_UNAME_SIZE 0xff
#define ADMIN_TOKEN_SIZE 0x11


/** handler del socket pasivo que atiende conexiones del protocolo propio */
void protocol_passive_accept(struct selector_key *key);


#endif
