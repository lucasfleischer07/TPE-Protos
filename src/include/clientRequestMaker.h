#ifndef _CLIENT_REQUEST_MAKER_H_
#define _CLIENT_REQUEST_MAKER_H_

#define PROGRAM_VERSION             1

#include "clientArgsParser.h"

#define BASE_REQUEST_DATA           21

// Indices de los campos en el mensaje serializado
#define FIELD_VERSION_INDEX         0
#define FIELD_TOKEN_INDEX           1
#define FIELD_METHOD_INDEX          17
#define FIELD_DLEN_INDEX            18
#define FIELD_DATA_INDEX            20

// Macros utiles para no tener que calcular el indice en cada paso
#define FIELD_VERSION(mem_pos)      mem_pos + FIELD_VERSION_INDEX
#define FIELD_TOKEN(mem_pos)        mem_pos + FIELD_TOKEN_INDEX
#define FIELD_METHOD(mem_pos)       mem_pos + FIELD_METHOD_INDEX
#define FIELD_DLEN(mem_pos)         mem_pos + FIELD_DLEN_INDEX
#define FIELD_DATA(mem_pos)         mem_pos + FIELD_DATA_INDEX

void serialize_request(struct client_request_args *args, char *token, char *buffer);


#endif