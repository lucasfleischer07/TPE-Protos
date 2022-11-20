/**
 * protocol.c -- archivo encargado del parseo del protocolo creado
 */
#include <string.h> //memset
#include <arpa/inet.h> //ntohs
#include <stdio.h>
#include <stdio.h> // printf

#include "protocol.h"
 
static uint8_t combinedlen[2] = {0};
static size_t username_len_with_null = 0;


/* Si se llego a este estado, ya se finalizo el parseo*/
bool protocol_is_done(enum protocol_state state){
    return state >= protocol_done;
}

/*  Acutaliza los bytes leidos y los que faltan leer para el proximo estado
    Por ejemplo: cuando termina de leer correctamente la version, setea los bytes leidos en 0 y los que faltan leer en
    el tamaño del token(con esto el proximo estado puede saber si leyo todo lo que deberia o no)
*/
static void remaining_set(struct protocol_parser *p, uint16_t len) {
    p->i = 0;
    p->len = len; 
}

/* Se actualiza el valor i(cantidad leida) por lo que hay que fijarse si le falta leer mas byes,
 * ya que recordar que se esta leyendo byte a byte
 */
static int remaining_is_done(struct protocol_parser *p) {
    return p->i >= p->len;
}

/** si el byte recivo no es 0x01, lo manda al estado de unsupported_version, sino pasa al estado token */
static enum protocol_state version(const uint8_t c, struct protocol_parser *p) {
    enum protocol_state next;
    switch (c) {
        case 0x01:
            remaining_set(p, TOKEN_SIZE);
            next = protocol_token;
            break;
        default:
            next = protocol_error_unsupported_version;
            break;
    }

    return next;
}

/** va leyendo y copiando el token, una vez que finalice se pasa el estado de method */
static enum protocol_state token(const uint8_t c, struct protocol_parser *p) {
    p->protocol->token[p->i++] = c;
    if (remaining_is_done(p))
        return protocol_method;
    return protocol_token;
}

/** Como method tiene un solo byte, la funcion method se llamara una unica vez, y se progresara
 *  como corresponda al metodo correcto, o caera en default y retornara unsoported_method
 *  Vemos que hay 2 casos muy distintivos, los que requieren de un DATA y los que no
*/
static enum protocol_state method(const uint8_t c, struct protocol_parser *p) {
    enum protocol_state next;

    p->protocol->method = c;
    switch (p->protocol->method) {
        case get_historic:
        case get_concurrent:
        case get_transfered:
        case get_proxyusers:
            p->protocol->method = c;
            next=protocol_done;
            break;
        case pop3disector:
        case add_proxyuser:
        case delete_proxyuser:
        case add_admin:
        case delete_admin:
            p->protocol->method = c;
            //Le aviso que DLEN debe leer 2 bytes
            remaining_set(p,DLEN_SIZE);
            next = protocol_dlen;
            break;        
        default:
            next = protocol_error_unsupported_method;
            break;
    }

    return next;
}


/** Como se dijo en el paso anterior, no siempre se llegara a este 
 *  estado
 *  Aca se presenta una dificultad, la longitud de DLEN dada en 2 bytes deben ser combinadas
 *  para esto se asume que vienen en BIGendean y para el resultado de 16 bits se utiliza el endian
 *  del sistema para evitar errores
*/
static enum protocol_state dlen(const uint8_t c, struct protocol_parser *p) {
    enum protocol_state next;

    combinedlen[p->i++] = c;
    next = protocol_dlen;
    //Si se leyeron los 2 bytes
    if (remaining_is_done(p)) {
        p->protocol->dlen = ntohs(*(uint16_t*)combinedlen); 
        switch (p->protocol->method) {
            //Para el caso de pop3, solo se pide un byte por lo que no se usa remaining_set
            case pop3disector:
                next = protocol_data;
                break;
            case add_proxyuser:
                remaining_set(p, p->protocol->dlen);
                next = protocol_data;
                break;
            case delete_proxyuser:
                remaining_set(p, p->protocol->dlen); 
                next = protocol_data;
                break;
            case add_admin:
                remaining_set(p, p->protocol->dlen);
                next = protocol_data;
                break;
            case delete_admin:
                remaining_set(p, p->protocol->dlen);
                next = protocol_data;
                break;
            default:
                next = protocol_error;
                break;
        }
    }

    return next;
}

static enum protocol_state data(const uint8_t c, struct protocol_parser *p) {
    enum protocol_state next;

    switch(p->protocol->method) { 
        case pop3disector:
            p->protocol->data.disector_data_params = c;
            next = protocol_done;
            break;
        
        case add_proxyuser: 
            // Si el primer caracter es 0 directamente tiro error ya que el usuario no puede ser vacio
            if (p->i == 0 && c == 0) {
                next = protocol_error_invalid_data;
                break;
            }
            // user0pass
            //Si el bit es un caracter alfanumerico, debe ser o nombre o contraseña
            //Se separa en dos etapas, antes del separador o despues del separador
            if (IS_ALNUM(c)) {
                if (p->separated == 0) {
                    p->protocol->data.add_proxy_user_param.user[p->i++] = c;
                } else {
                    p->protocol->data.add_proxy_user_param.pass[p->i - username_len_with_null] = c; //pass[0] = c
                    p->i++;
                }
                next = protocol_data;
            } else if (c == 0 && p->separated == 0) { 
                // se econtro el primer separador \0, lo marco y  pongo el null terminated en el username
                p->protocol->data.add_proxy_user_param.user[p->i++] = c;
                p->separated = 1;
                username_len_with_null = p->i;
                next = protocol_data;
            } else { 
                // Si no es alfanumerico y ya hubo un separador, entonces hubo un error por parte del cliente en el data
                next = protocol_error_invalid_data;
                break;
            }
            //Si se termino de procesar el data y no hubieron errores, se pasa a protocol_done
            if (remaining_is_done(p)) {
                p->protocol->data.add_proxy_user_param.pass[p->i] = 0; // null terminated para password
                next = protocol_done;
                p->separated = 0;
                break;
            }

            break;

        case delete_proxyuser:
            //Se lee cada caracter alfanumerico, si no lo es, es un error
            if (IS_ALNUM(c)) {
                p->protocol->data.user[p->i++] = c;
                next = protocol_data;
            } else {
                next = protocol_error_invalid_data;
                break;
            }
            //Una vez se procesa data completo se le pone el null terminated a user y va a protocol_done
            if (remaining_is_done(p)) {
                p->protocol->data.user[p->i] = 0; 
                next = protocol_done;
                break;
            }
            
            break;

        case add_admin:
            // parecico a add_proxy_user
            if (p->i == 0 && c == 0) {
                next = protocol_error_invalid_data;
                break;
            }

            if (IS_ALNUM(c)) {
                if (p->separated == 0) {
                    p->protocol->data.add_admin_user_param.user[p->i++] = c;
                } else {
                    p->protocol->data.add_admin_user_param.token[p->i - username_len_with_null] = c;
                    p->i++;
                }
                next = protocol_data;
            } else if (c == 0 && p->separated == 0) { // primer separador \0 pongo el null terminated en el username
                p->protocol->data.add_admin_user_param.user[p->i++] = c;
                p->separated = 1;
                username_len_with_null = p->i;
                next = protocol_data;
            } else { // Si no es alfanumerico ni fue el primer 0 separador entonces no es un dato valido
                next = protocol_error_invalid_data;
                break;
            }

            if (remaining_is_done(p)) {
                p->protocol->data.add_admin_user_param.token[p->i] = 0; // null terminated para password
                next = protocol_done;
                p->separated = 0;
                break;
            }
            
            break;

        case delete_admin:
            if (IS_ALNUM(c)) {
                p->protocol->data.user[p->i++] = c;
                next = protocol_data;
            } else {
                next = protocol_error_invalid_data;
                break;
            }

            if (remaining_is_done(p)) {
                p->protocol->data.user[p->i] = 0; // null terminated para username
                next = protocol_done;
                break;
            }
            
            break;
        default:
            next = protocol_error_invalid_data;
            break;
    }

    return next;
}



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

/** Funcion que se encarga de pasar los errores al buffer */
extern int protocol_error_marshall(buffer *b, struct protocol_parser *p) {
    enum protocol_state st = p->state;

    size_t n;
    buffer_write_ptr(b, &n);

    if (n < 4)
        return -1;

    // STATUS
    switch(st) {
        case protocol_error_unsupported_version:
            buffer_write(b, protocol_status_invalid_version);
            break;
        case protocol_error_invalid_token:
            buffer_write(b, protocol_status_error_auth);
            break;
        case protocol_error_unsupported_method:
            buffer_write(b, protocol_status_invalid_method);
            break;
        case protocol_error_invalid_data:
            buffer_write(b, protocol_status_invalid_data);
            break;
        default:
            buffer_write(b, protocol_status_server_error);
            break;
    }

   
    union data_len datalen;
    datalen.len = htons(1); 

    // DLEN
    buffer_write(b, datalen.byte[0]);
    buffer_write(b, datalen.byte[1]);

    // DATA
    buffer_write(b, 0);

    return 4;
}


extern int protocol_marshall(buffer *b, enum protocol_response_status status, uint16_t dlen, void *data, bool numeric_data) {
    // llenar status y dlen primero, checkeando el espacio que hay en el buffer (si te quedas sin espacio en el buffer retornas -1)
    size_t n;
    buffer_write_ptr(b, &n);

    if (n < (size_t) dlen + 3)
        return -1;
    
   
    union data_len response_len;
    response_len.len = htons(dlen); 
    
    buffer_write(b, status);
    //mando dlen
    buffer_write(b, response_len.byte[0]);
    buffer_write(b, response_len.byte[1]);

    if (numeric_data) {
        uint8_t numeric_response[4];

        uint32_t number = htonl(*((uint32_t*)data));
        memcpy(numeric_response, &number, sizeof(uint32_t));

        for (int i = 0; i < 4; i++) {
            buffer_write(b, numeric_response[i]);
        }
    } else {
        uint8_t *databytes = (uint8_t *) data; 
        if (databytes == NULL) {
            buffer_write(b, 0);
        } else {
            for (uint16_t i = 0; i < dlen; i++) {
                buffer_write(b, databytes[i]);
            }
        }
    }

    return dlen + 3;
}
