#include <string.h>
#include "clientRequestMaker.h"

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
        //    functionTODO(args, buffer)                                    // hay que contemplar los diferentes casos de data
            break;
        default:
            // should not get here
            break;
    }
}

