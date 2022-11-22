#include <string.h>
#include "clientArgsParser.h"
#include "clientRequestMaker.h"


static void serialize_config_data(struct client_request_args *args, char* buffer);


/** serializa el request en el buffer */
void serialize_request(struct client_request_args *args, char* token, char *buffer){
    buffer[FIELD_VERSION_INDEX] = PROGRAM_VERSION;
    memcpy(FIELD_TOKEN(buffer), token, TOKEN_SIZE);
    
    buffer[FIELD_METHOD_INDEX] = args->method;

    // Sending in network order
    uint16_t dlen = htons(args->dlen);
    memcpy(FIELD_DLEN(buffer), &dlen, sizeof(uint16_t));

    switch(args->method){
        case historic_connections:
        case concurrent_connections:
        case transferred_bytes:
        case proxy_users_list:
            memcpy(FIELD_DATA(buffer), &args->data.optional_data, sizeof(uint8_t)); // data = 0 en todos estos casos
            break;
        case toggle_disector:
        case add_proxy_user:
        case del_proxy_user:
        case add_admin_user:
        case del_admin_user:
            serialize_config_data(args, buffer);                                    // hay que contemplar los diferentes casos de data
            break;
        default:
            // should not get here
            break;
    }
}

/** por cada metodo adapta el data tal como pide el protocolo*/
static void serialize_config_data(struct client_request_args *args, char *buffer){
    uint8_t disector_value;
    size_t username_len;
    size_t extra_param_len;
    
    switch(args->method){
        case toggle_disector:
            disector_value = args->data.disector_data_params;
            memcpy(FIELD_DATA(buffer), &disector_value, sizeof(uint8_t));
            
            break;
        case add_proxy_user:
            username_len = strlen(args->data.add_proxy_user_params.user);
            memcpy(FIELD_DATA(buffer), args->data.add_proxy_user_params.user, username_len);
            
            buffer[FIELD_DATA_INDEX + username_len] = args->data.add_proxy_user_params.separator;
            
            extra_param_len = strlen(args->data.add_proxy_user_params.pass);
            memcpy(FIELD_DATA(buffer) + username_len + 1, args->data.add_proxy_user_params.pass, extra_param_len);

            break;
        case add_admin_user:
            username_len = strlen(args->data.add_admin_user_params.user);
            memcpy(FIELD_DATA(buffer), args->data.add_admin_user_params.user, username_len);
            
            buffer[FIELD_DATA_INDEX + username_len] = args->data.add_admin_user_params.separator;
            
            extra_param_len = strlen(args->data.add_admin_user_params.token);
            memcpy(FIELD_DATA(buffer) + username_len + 1, args->data.add_admin_user_params.token, extra_param_len);

            break;
        case del_proxy_user:
        case del_admin_user:
            memcpy(FIELD_DATA(buffer), args->data.user, args->dlen);
            break;
        default:    //No deberia llegar aca
            break;
    }
}
