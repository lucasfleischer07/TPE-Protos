/**
 * protocol.c -- archivo encargado del parseo del protocolo creado
 */
#include <string.h> //memset
#include <arpa/inet.h> //ntohs
#include <stdio.h>
#include <stdio.h> // printf

#include "../include/protocol.h"

// Si se llego a este estado, ya se finalizo el parseo
bool protocol_is_done(enum protocol_state state){
    return state >= protocol_done;
}

// Funcion principal de parseo, es la que consume byte a byte y delega el procesamiento
extern enum protocol_state protocol_consume(buffer *b, struct protocol_parser *p) {
    enum protocol_state st = p->state;

    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = protocol_parser_feed(p, c); // cargamos 1 solo byte
        if (protocol_is_done(st))
            break;
    }
    return st;
}
