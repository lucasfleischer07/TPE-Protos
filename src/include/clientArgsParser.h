#ifndef _CLIENT_ARGS_PARSER_H_
#define _CLIENT_ARGS_PARSER_H_

#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdlib.h>


/** Define el addr default, el puerto default y los tamaños de las partes del protocolo*/
#define DEFAULT_CONF_ADDR           "127.0.0.1"
#define DEFAULT_CONF_PORT           "8080"

#define DEFAULT_DISECTORS_ENABLED   true

#define DATA_SIZE                   65535
#define TOKEN_SIZE                  16
#define USERNAME_SIZE               0xFF
#define PASSWORD_SIZE               0xFF

#define TOKEN_ENV_VAR_NAME          "MONITOR_TOKEN"

/** Similar a como esta definido en protocol.c, hay que hacer los enums */

enum method {
    historic_connections    = 0,
    concurrent_connections  = 1,
    transferred_bytes       = 2,
    toggle_disector         = 3,
    add_proxy_user          = 4,
    del_proxy_user          = 5,
    add_admin_user          = 6,
    del_admin_user          = 7,
    proxy_users_list        = 8,
};

enum config_disector_data {
    disector_off    = 0,
    disector_on     = 1,
};

struct config_add_proxy_user {
    char        user[USERNAME_SIZE];
    char        separator;
    char        pass[PASSWORD_SIZE];
};

struct config_add_admin_user {
    char        user[USERNAME_SIZE];
    char        separator;
    char        token[TOKEN_SIZE];
};

union data {
    uint8_t                         optional_data;          // To send 0 according to RFC
    char                            user[USERNAME_SIZE];
    enum   config_disector_data     disector_data_params;
    struct config_add_proxy_user    add_proxy_user_params;
    struct config_add_admin_user    add_admin_user_params;
};

struct client_request_args {
    enum method     method;
    uint16_t        dlen;
    union data      data;
};

enum ip_version {
    ipv4 = 4,
    ipv6 = 6
};


/**
 * Interpreta los argumentos ingresados y llena los args con defaults si no los ingreso. Puede cortar
 * la ejecución si falta informacion.
 */
size_t parse_args(const int argc, char **argv, struct client_request_args *args, char *token, struct sockaddr_in *sin4, struct sockaddr_in6 *sin6, enum ip_version *ip_version);

#endif