/**
 * protocolnio.c -- archivo responsable del manejo del socket del usuario del servidor, delega el pareseo a protocol.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../include/buffer.h"
#include "../include/protocolnio.h"
#include "../include/socks5nio.h"

#define BUFFER_SIZE 4096
#define N(x) (sizeof(x)/sizeof((x)[0]))

struct protocol_st {
    buffer *rb, *wb;
    struct protocol protocol;
    struct protocol_parse parser;
    enum protocol_response_status status;
};


struct connection {
    /** informacion del usuario del protocolo*/
    int client_fd;

    /** Contiene el estado de la coneccion, con el parser y el estado */
    struct protocol_st request;

    /** buffers para ser usados por read_buffer y write_buffer */
    uint8_t raw_buff_a[BUFFER_SIZE], raw_buff_b[BUFFER_SIZE];
    buffer  read_buffer, write_buffer;

    /** siguiente en la pool */
    struct connection *next;
};

/** Pool de structs connection para ser reusados */
static const unsigned max_pool = 5;  // tamaño max
static unsigned pool_size = 0; // tamaño actual
static struct connection *pool = 0;     // pool propiamente dicho
