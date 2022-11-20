#ifndef SOCKS5_NIO_H
#define SOCKS5_NIO_H

#include <netdb.h>
#include "selector.h"
#define MAX_USERS 10
#define USERNAME_SIZE_SOCKS5 0xff


/** handler del socket pasivo que atiende conexiones socksv5 */
void socksv5_passive_accept(struct selector_key *key);

/** libera pools internos */
void socksv5_pool_destroy(void);

/** entrega la lista de usuarios con formato <usuario>\0<usuario>, tal como la pasan en el request del protocolo */
uint16_t socksv5_get_users(char unames[MAX_USERS * USERNAME_SIZE_SOCKS5]);

/** registra usuarios nuevos */
int socksv5_register_user(char *uname, char *passwd);

/** elimina el usuario del registro */
int socksv5_unregister_user(char *uname);


/** activa o desactiva el disector */
void socksv5_toggle_disector(bool to);

/** retorna la cantidad de conecciones totales al proxy */
uint32_t socksv5_historic_connections();

/** retorna la cantidad de conecciones actuales al proxy */
uint32_t socksv5_current_connections();

/** retorna la cantidad de bytes transferidos */
uint32_t socksv5_bytes_transferred();

#endif