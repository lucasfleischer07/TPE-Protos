#include <stdio.h>     
#include <stdlib.h>    
#include <limits.h>    
#include <string.h>    
#include <errno.h>
#include <getopt.h>

#include "clientArgsParser.h"
#include "client.h"
#define EXTRA_PARAMS 3

static size_t token_check(const char *src, char *dest_token, char *progname);



/** Chequea que s sea un puerto valido */
static unsigned short port(const char *s, char* progname) {
    char *end     = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)  || sl < 0 || sl > USHRT_MAX) {
        fprintf(stderr, "%s: invalid port %s, shoul d be an integer in the range of 1-65535.\n", progname, s);
        exit(1);
    }
    return (unsigned short)sl;
}

/** muestra las opciones de argumentos del cliente */
static void usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]... TOKEN [DESTINATION] [PORT]\n"
        "Options:\n"
        "-h                  imprime los comandos del programa y termina.\n"
        "-r <user!pass>      agrega un usuario del proxy con el nombre y contraseña indicados.\n"
        "-R <user!token>     agrega un usuario administrador con el nombre y token indicados.\n"
        "-c                  imprime la cantidad de conexiones concurrentes del server.\n"
        "-C                  imprime la cantidad de conexiones históricas del server.\n"
        "-b                  imprime la cantidad de bytes transferidos del server.\n"
        "-l                  imprime una lista con los usuarios del proxy.\n"
        "-d <user>           borra el usuario del proxy con el nombre indicado.\n"
        "-D <user>           borra el usuario administrador con el nombre indicado.\n"
        "-O                  enciende el password disector en el server.\n"
        "-F                  apaga el password disector en el server.\n"
        "-v                  imprime la versión del programa y termina.\n"
        "\n",
        progname);
    exit(1);
}

/** setea el resto de la estructura en dlen = 1 y data 0, ya que este metodo no requiere data*/
static void set_no_data_method(struct client_request_args *args) {
    args->dlen = 1;
    args->data.optional_data = 0;
}

/** checkea si la longitud del nombre o la contraseña esta dentro de los limites*/
static size_t string_check(const char *src, char *dest, char* field_name, size_t max_len, char* progname){
    size_t str_len;
    if((str_len = strlen(src)) > max_len){
        fprintf(stderr, "%s: invalid username length (%zu), should be of at most %zu characters.\n", progname, str_len, max_len);
        exit(1);
    }
    memcpy(dest, src, str_len);
    return str_len;
}

/** carga el username y password en la estructura declarada, que esta dentro de data*/
static size_t username_with_password(char *src, struct config_add_proxy_user *user_params, char *progname){
    size_t str_len;
    char *separator = strchr(src, '!');

    if(separator == NULL) {
        fprintf(stderr, "%s: missing password for user %s.\n", progname, src);
        exit(1);
    } else if(src[0] == '!') {
        fprintf(stderr, "%s: missing username for password %s.\n", progname, separator + 1);
        exit(1);
    }
    //El username sera hasta el separador, y el password sera desde el separador + 1 hasta el final 
    char *username = strtok(src, "!");
    char *password = separator + 1;

    str_len = string_check(username, user_params->user, "username", USERNAME_SIZE, progname);
    user_params->separator = 0;
    str_len++;
    str_len += string_check(password, user_params->pass, "password", PASSWORD_SIZE, progname);
    
    return str_len;
}

/** parecido a suername_with_password */
static size_t username_with_token(char *src, struct config_add_admin_user *admin_params, char *progname){
    size_t str_len;
    char *separator = strchr(src, '!');

    if(separator == NULL){
        fprintf(stderr, "%s: missing token for user %s.\n", progname, src);
        exit(1);
    } else if(src[0] == '!'){
        fprintf(stderr, "%s: missing username for token %s.\n", progname, separator + 1);
    }

    char* username = strtok(src, "!");
    char* token = separator + 1;

    str_len = string_check(username, admin_params->user, "username", USERNAME_SIZE, progname);
    admin_params->separator = 0;
    str_len++;
    str_len += token_check(token, admin_params->token, progname);
    return str_len;
}

/** imprime la version del protocolo*/
static void version(void) {
    fprintf(stderr, "Cliente Protocolo de Monitoreo de Servidor Proxy / Version 1\n"
                    "Protocolos de Comunicacion grupo 7, ITBA \n");
}

/** chequea que el token ingresado este bien formado, de ser asi lo guarda */
static size_t token_check(const char *src, char *dest_token, char *progname){
    size_t token_len;
    if((token_len = strlen(src)) != TOKEN_SIZE){
        fprintf(stderr, "%s: invalid toklen length (%zu), should be of exactly %d characters.\n", progname, token_len, TOKEN_SIZE);
        exit(1);
    }
    memcpy(dest_token, src, TOKEN_SIZE);
    return TOKEN_SIZE;
}

/** prueba si la ip ingresada es v4 o v6, y las guarda. Si no es ninguna de las 2 printea mensaje de error*/
static enum ip_version ip_check(const char* src, struct sockaddr_in *sin4, struct sockaddr_in6 *sin6, char* progname){
    if(inet_pton(AF_INET, src, &sin4->sin_addr) > 0){
        sin4->sin_family = AF_INET;
        return ipv4;
    } else if(inet_pton(AF_INET6, src, &sin6->sin6_addr.s6_addr) > 0) {
        sin6->sin6_family = AF_INET6;
        return ipv6;
    } else {
        fprintf(stderr, "%s: invalid ip %s sent.\n", progname, src);
        exit(1);
    }
}

/** setea el puerto ingresado por argumento */
static void port_check(const char* src, struct sockaddr_in *sin4, struct sockaddr_in6 *sin6, enum ip_version *ip_version, char* progname){
    if(*ip_version != ipv4 && *ip_version != ipv6){
        fprintf(stderr, "%s: invalid ip sent.\n", progname);
        exit(1);
    }

    uint16_t network_port = htons(port(src, progname));
    if(*ip_version == ipv4){
        sin4->sin_port = network_port;
    } else {
        sin6->sin6_port = network_port;
    }
}


size_t parse_args(const int argc, char **argv, struct client_request_args *args, char *token,struct sockaddr_in *sin4, struct sockaddr_in6 *sin6, enum ip_version *ip_version) {
    memset(sin4, 0, sizeof(*sin4));
    memset(sin6, 0, sizeof(*sin6));

    size_t req_idx;

    sin4->sin_family = AF_INET;
    sin4->sin_port = htons(port(DEFAULT_CONF_PORT, argv[0]));
    inet_pton(AF_INET, DEFAULT_CONF_ADDR, &sin4->sin_addr);
    *ip_version = ipv4;

    for(req_idx = 0 ; req_idx < MAX_CLIENT_REQUESTS ; req_idx++){
        //Chequea si hay mas argumentos por parsear, si hay argumento lo carga en optarg, una variable externa
        int c = getopt(argc, argv, ":hcCblOFr:R:d:D:hv");
        if (c == -1){
            break;
        }

        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'c':
                // Get concurrent connections
                set_no_data_method(&args[req_idx]);
                args[req_idx].method = concurrent_connections;
                break;
            case 'C':
                // Get historic connections
                set_no_data_method(&args[req_idx]);
                args[req_idx].method = historic_connections;
                break;
            case 'b':
                // Get bytes transferred
                set_no_data_method(&args[req_idx]);
                args[req_idx].method = transferred_bytes;
                break;
            case 'l':
                // Get list of proxy users
                set_no_data_method(&args[req_idx]);
                args[req_idx].method = proxy_users_list;
                // TODO: Show list of proxy users
                break;
            case 'O':
                // Turns on password disector
                args[req_idx].method = toggle_disector;
                args[req_idx].dlen = 1;
                args[req_idx].data.disector_data_params = disector_on;
                break;
            case 'F':
                // Turns off password disector
                args[req_idx].method = toggle_disector;
                args[req_idx].dlen = 1;
                args[req_idx].data.disector_data_params = disector_off;
                break;
            case 'r':
                // Adds proxy user
                args[req_idx].method = add_proxy_user;
                args[req_idx].dlen = username_with_password(optarg, &args[req_idx].data.add_proxy_user_params, argv[0]);
                break;
            case 'R':
                // Adds admin user
                args[req_idx].method = add_admin_user;
                args[req_idx].dlen = username_with_token(optarg, &args[req_idx].data.add_admin_user_params, argv[0]);
                break;
            case 'd':
                // Deletes proxy user
                args[req_idx].method = del_proxy_user;
                args[req_idx].dlen = string_check(optarg, args[req_idx].data.user, "username", USERNAME_SIZE, argv[0]);
                break;
            case 'D':
                // Deletes admin user
                args[req_idx].method = del_admin_user;
                args[req_idx].dlen = string_check(optarg, args[req_idx].data.user, "username", USERNAME_SIZE, argv[0]);
                break;
            case 'v':
                // Prints program version
                version();
                exit(0);
                break;
            case ':':
                // Option missing, help is served
                fprintf(stderr, "%s: missing value for option -%c.\n", argv[0], optopt);
                usage(argv[0]);
                exit(1);
                break;
            case '?':
                fprintf(stderr, "%s: invalid option -%c.\n", argv[0], optopt);
                usage(argv[0]);
                exit(1);
            default:
                // no deberia llegar aca
                break;
        }
    }

    if(optind == argc){
        fprintf(stderr, "%s: missing token for client request.\n", argv[0]);
        exit(1);
    }

    int extra_runs = 0;

    do {
        switch(extra_runs)
        {
            case 0:
                //
                token_check(argv[optind], token, argv[0]);
                break;
            case 1:
                *ip_version = ip_check(argv[optind], sin4, sin6, argv[0]);
                break;
            case 2:
                port_check(argv[optind], sin4, sin6, ip_version, argv[0]);
                break;
        }
        extra_runs++;
        optind++;
    } while(extra_runs < EXTRA_PARAMS && optind < argc);
    //Quedan argumentos por procesar, es un error
    if(optind < argc){
        fprintf(stderr, "%s: sent too many arguments. run '%s -h' for more information.\n", argv[0], argv[0]);
        exit(1);
    }

    return req_idx;
}