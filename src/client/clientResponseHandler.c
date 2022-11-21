#include "clientResponseHandler.h"


/** maneja la respuesta de los metodos que conllevaban data*/
void handle_get_ok_status(struct client_request_args arg, uint8_t *buf, uint8_t *combinedlen, uint8_t *numeric_data_array, uint32_t *numeric_response) {
    // para evitar problemas con el endian
    combinedlen[0] = buf[1];
    combinedlen[1] = buf[2]; 
    uint16_t dlen = ntohs(*(uint16_t*)combinedlen); // obtengo el dlen
    switch (arg.method) {
        case historic_connections:      // recibe uint32 (4 bytes)
        case concurrent_connections:    // recibe uint32 (4 bytes)
        case transferred_bytes:         // recibe uint32 (4 bytes)
            for (int k = 0, j = 3; k < 4; k++) {    // copio a partir del byte 4, los 4 proximos bytes
                numeric_data_array[k] = buf[j++];
            }
            *numeric_response = ntohl(*(uint32_t*)numeric_data_array);
            if(arg.method == historic_connections) {
                printf("The amount of historic connections is: %u\n", *numeric_response);
            } else {
                printf("The amount of %s is: %u\n",  arg.method == concurrent_connections ? "concurrent connections" : "transferred bytes", *numeric_response);
            }
            break;
        case proxy_users_list:
            printf("Printing proxy user list:  \n");
            for (uint16_t k = 3; k < dlen + 3; k++) {   //copio a partir del byte 4, hasta que llegue a dlen
                if (buf[k] == 0) {
                    putchar('\n');
                } else {
                    putchar(buf[k]);
                }
            }
            putchar('\n'); // el ultimo nombre de la lista no tiene \0
            break;
    default:
        break;
    }
}

/** maneja la respuesta de los metodos que no requieren data, si el status es ok printean siempre el mismo mensaje*/
void handle_config_ok_status(struct client_request_args arg) {
    switch (arg.method) {
        case toggle_disector:
            printf("The pop3 password disector is now: %s\n", arg.data.disector_data_params == disector_off ? "OFF" : "ON");
            break;
        case add_proxy_user:
            printf("The proxy user: '%s' is now added to the server\n", arg.data.add_proxy_user_params.user);
            break;
        case del_proxy_user:
            printf("The proxy user: '%s' is now deleted in the server\n", arg.data.add_proxy_user_params.user);
            break;
        case add_admin_user:
            printf("The admin: '%s' is now added in the server\n", arg.data.add_proxy_user_params.user);
            break;
        case del_admin_user:
            printf("The admin: '%s' is now deleted in the server\n", arg.data.add_proxy_user_params.user);
            break;
    }      
}

/** maneja los casos de error de la respuesta y printea un diferente mensaje dependiendo de cada caso */
void handle_error_response (struct client_request_args *args, enum protocol_resp_status resp_status) {
    switch (resp_status) {
        case protocol_resp_status_invalid_version:
            printf("The version of the request you have sent is incorrect!\n");
            break;
        case protocol_resp_status_invalid_method:
            printf("The method of the request you have sent is incorrect!\n");
            break;
        case protocol_resp_status_invalid_data:
            // Aca depende del metodo para el mensaje imprimido
            switch (args->method) {
                case toggle_disector:
                    printf("Error configuring the pop3 disector on/off, data must be 0 or 1!\n");
                    break;
                case add_proxy_user:
                    printf("Error adding the proxy user, user and password should be alphanumeric or user already exist!\n");
                    break;
                case del_proxy_user:
                    printf("Error deleting the proxy user, user name should be alphanumeric or user does not exist\n");
                    break;
                case add_admin_user:
                    printf("Error adding the admin, admin and token should be alphanumeric or admin already exist!\n");
                    break;
                case del_admin_user:
                    printf("Error deleting the admin, admin name should be alphanumeric, admin does not exist or is default admin!\n");
                    break;
                default:
                    printf("The data of the request you have sent is incorrect!\n");
                    break;
                }
            break;
        case protocol_resp_status_error_auth:
            printf("The token of the request you have sent is incorrect!\n");
            break;
        case protocol_resp_status_server_error:
            printf("The server could not resolve your request!\n");
            break;
        default:
            break;
    }
}


/** funcion principal, que recibe la respuesta y dependiendo del status ejecuta diferentes funciones*/
void process_response (uint8_t c, struct client_request_args *args, uint8_t *buf, uint8_t *combinedlen, uint8_t *numeric_data_array, uint32_t *numeric_response) {
        if (c == protocol_resp_status_ok) {
            if (args->method == historic_connections || args->method == concurrent_connections || args->method ==  transferred_bytes || args->method ==  proxy_users_list) 
                handle_get_ok_status(*args, buf, combinedlen, numeric_data_array, numeric_response); 
            else
                handle_config_ok_status(*args);
        } else {
            handle_error_response (args, c);
        }
}