#ifndef SOCKS5_NIO_H
#define SOCKS5_NIO_H

#include <netdb.h>
#include "selector.h"

#define MAX_USERS 10



/** handler del socket pasivo que atiende conexiones socksv5 */
void socksv5_passive_accept(struct selector_key *key);

/** libera pools internos */
void socksv5_pool_destroy(void);

/** registra usuarios nuevos */
int socksv5_register_user(char *uname, char *passwd);

/** activa o desactiva el disector */
void socksv5_toggle_disector(bool to);

#endif