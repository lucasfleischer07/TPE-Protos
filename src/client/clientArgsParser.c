#include <stdio.h>     
#include <stdlib.h>    
#include <limits.h>    
#include <string.h>    
#include <errno.h>
#include <getopt.h>

#include "clientArgsParser.h"




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
        int c = getopt(argc, argv, ":hcCbanNu:U:d:D:hv");
        if (c == -1){
            break;
        }

        switch (c) {
            case 'h':
                //case options
                exit(0);
                break;
            case 'c':
                // Get concurrent connections
                //setear no data
                args[req_idx].method = concurrent_connections;
                break;
            case 'C':
                // Get historic connections
                //setear no data
                args[req_idx].method = historic_connections;
                break;
            case 'b':
                // Get bytes transferred
                //setear no data
                args[req_idx].method = transferred_bytes;
                break;
            case 'a':
                // Get list of proxy users
                //setear no data
                args[req_idx].method = proxy_users_list;
                // TODO: Show list of proxy users
                break;
            case 'n':
                // Turns on password disector
                args[req_idx].method = toggle_disector;
                args[req_idx].dlen = 1;
                args[req_idx].data.disector_data_params = disector_on;
                break;
            case 'N':
                // Turns off password disector
                args[req_idx].method = toggle_disector;
                args[req_idx].dlen = 1;
                args[req_idx].data.disector_data_params = disector_off;
                break;
            case 'u':
                // Adds proxy user
                args[req_idx].method = add_proxy_user;
                //leer el nombre y contraseña
                break;
            case 'U':
                // Adds admin user
                args[req_idx].method = add_admin_user;
                //leer el nombre y token
                break;
            case 'd':
                // Deletes proxy user
                args[req_idx].method = del_proxy_user;
                //chequear nombre
                break;
            case 'D':
                // Deletes admin user
                args[req_idx].method = del_admin_user;
                //chequear nombre
                break;
            case 'v':
                // Prints program version
                //imprimir version
                exit(0);
                break;
            case ':':
                // Option missing, help is served
                fprintf(stderr, "%s: missing value for option -%c.\n", argv[0], optopt);
                //case options
                exit(1);
                break;
            case '?':
                fprintf(stderr, "%s: invalid option -%c.\n", argv[0], optopt);
                //case options
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