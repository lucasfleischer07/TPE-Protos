#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>

#define MAX_USERS 10

#define DEFAULT_SOCKET_ADDR_V4          "0.0.0.0"
#define DEFAULT_SOCKET_ADDR_V6       "::0"
#define DEFAULT_SOCKET_PORT          1080

#define DEFAULT_CONF_ADDR           "127.0.0.1"
#define DEFAULT_CONF_ADDR_V6        "::1"
#define DEFAULT_CONF_PORT           8080

struct users {
    char *name;
    char *pass;
};

struct doh {
    char           *host;
    char           *ip;
    unsigned short  port;
    char           *path;
    char           *query;
};

struct socks5args {
    char           *socks_addr;
    unsigned short  socks_port;
    bool            is_default_socks_addr;

    char *          mng_addr;
    unsigned short  mng_port;
    bool            is_default_mng_addr;

    bool            disectors_enabled;

    struct doh      doh;
    struct users    users[MAX_USERS];
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void parse_args(const int argc, char **argv, struct socks5args *args);

#endif

