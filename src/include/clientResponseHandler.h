#ifndef _CLIENT_RESPONSE_HANDLER_H_
#define _CLIENT_RESPONSE_HANDLER_H_

#include <string.h>
#include <stdio.h>
#include "clientRequestMaker.h"
#include "clientArgsParser.h"

/** Valores posibles del status del response, los mismos que en protocol.h */
enum protocol_resp_status {
    protocol_resp_status_ok              = 0x00,
    protocol_resp_status_invalid_version = 0x01,
    protocol_resp_status_invalid_method  = 0x02,
    protocol_resp_status_invalid_data    = 0x03,
    protocol_resp_status_error_auth      = 0x04,
    protocol_resp_status_server_error    = 0x05,
};

void process_response (uint8_t c, struct client_request_args *args, uint8_t *buf, uint8_t *combinedlen, uint8_t *numeric_data_array, uint32_t *numeric_response);

#endif