/**
 * protocol.c -- archivo encargado del parseo del protocolo creado
 */
#include <string.h> //memset
#include <arpa/inet.h> //ntohs
#include <stdio.h>
#include <stdio.h> // printf

#include "protocol.h"
 




/** le da el byte al parser, dependiendo en el estado en el que se encuentra, se procesa el byte y
 *  se determina a que estado seguir.
 */
static enum protocol_state protocol_parser_feed(struct protocol_parser *p, const uint8_t c) {
    enum protocol_state next;

    switch(p->state) {
        case protocol_version:
            next = version(c, p);
            break;
        case protocol_token:
            next = token(c, p);
            break;
        case protocol_method:
            next = method(c, p);
            break;
        case protocol_dlen:
            next = dlen(c, p);
            break;
        case protocol_data:
            next = data(c, p);
            break;
        case protocol_done:
        case protocol_error:
        case protocol_error_unsupported_version:
        case protocol_error_invalid_token:
        case protocol_error_unsupported_method:
        case protocol_error_invalid_data:
            next = p->state;
            break;
        default:
            next = protocol_error;
            break;
    }

    return p->state = next;
}



/* Funcion principal de parseo, es la que consume byte a byte y delega el procesamiento*/
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


/** Arranco en el estado de protocol_version, el inicio del mensaje deberia ser y le doy el parser*/
void protocol_parser_init(struct protocol_parser *p) {
    p->state = protocol_version;
    memset(p->protocol, 0, sizeof(*(p->protocol)));
}