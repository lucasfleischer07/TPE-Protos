/**
 * protocolnio.c -- archivo responsable del manejo del socket del usuario del servidor, delega el pareseo a protocol.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "buffer.h"
#include "protocolnio.h"
#include "socks5nio.h"
#include "selector.h"
#include "protocol.h"


#define BUFFER_SIZE 4096
#define N(x) (sizeof(x)/sizeof((x)[0]))


struct protocol_st {
    buffer                       *rb, *wb;
    struct protocol               protocol;
    struct protocol_parser        parser;
    enum protocol_response_status status;
};


struct connection {
    /** informacion del usuario del protocolo*/
    int                           client_fd;

    /** Contiene el estado de la coneccion, con el parser y el estado */
    struct protocol_st             request;

    /** buffers para ser usados por read_buffer y write_buffer */
    uint8_t raw_buff_a[BUFFER_SIZE], raw_buff_b[BUFFER_SIZE];
    buffer  read_buffer, write_buffer;

    /** siguiente en la pool */
    struct connection *next;
};

#define ATTACHMENT(key) ((struct connection *)(key)->data)

/** Pool de structs connection para ser reusados */
static const unsigned       max_pool = 5;  // tamaño max
static unsigned             pool_size = 0; // tamaño actual
static struct connection    *pool = 0;     // pool propiamente dicho


static struct connection *connection_new(int client_fd) {
    struct connection *ret;

    if (pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret = pool;
        pool = pool->next;
        ret->next = 0; // lo sacamos de la pool para retornarlo y usarlo
    }

    if (ret == NULL)
        return ret;
    
    memset(ret, 0x00, sizeof(*ret)); // inicializamos en 0 todo

    ret->client_fd = client_fd;

    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);
    return ret;
}



static void protocol_init(struct connection *state) {
    struct protocol_st *d    = &state->request;
    d->rb                   = &(state->read_buffer);
    d->wb                   = &(state->write_buffer);
    d->parser.protocol       = &d->protocol;
    d->status               = protocol_status_server_error;
    protocol_parser_init(&d->parser);
}

/* handlers de seleccion de una coneccion entre el cliente y el server, similar a socks5nio*/
static void protocol_read   (struct selector_key *key);


static const struct fd_handler protocol_handler = {
    .handle_read   = protocol_read,  // selector despierta para lectura
    
};


///////////////// Request handling ////////////////////////////////////////////
// read_handler

static void protocol_finish(struct selector_key* key);

static void protocol_process(struct selector_key *key, struct protocol_st *d);

/** lee todos los bytes de la request e inicia el proceso correspondiente */
static void protocol_read(struct selector_key *key) {
    struct protocol_st *d = &ATTACHMENT(key)->request;

    buffer *b       = d->rb;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(b, &count);
    n = recv(key->fd, ptr, count, 0);

    if (n <= 0) {
        protocol_finish(key);
    } else {
        buffer_write_adv(b, n);
        int st = protocol_consume(b, &d->parser);
        if (protocol_is_done(st)) {
            if (st >= protocol_error) {
                if (-1 == protocol_error_marshall(d->wb, &d->parser)) {
                    abort();
                }
            } else {
                protocol_process(key, d);    // ejecuta la accion pedida y escribe la response en el buffer
            }
            selector_set_interest_key(key, OP_WRITE);   // pasamos al protocol_write() cuando podamos escribir
        }
    }
}




/** Solo debe retornar -1 en caso de error terminal en la conexion, si es un error en la request se pasa al paso de escritura (y retorno 0 por ej)
 *  en otro caso, procesa el metodo del request */ 
static void protocol_process(struct selector_key *key, struct protocol_st *d) {
    uint8_t *data = NULL;
    // uint32_t *data = malloc(sizeof(uint32_t));
    uint16_t dlen = 1;
    bool numeric_data = false;
    int error_response = 0;
    //Chequea que el token sea uno valido
    if (!protocol_user_is_admin(d->parser.protocol->token)) {
        d->status = protocol_status_error_auth;
        goto finally;
    }

    switch (d->parser.protocol->method) {
        case get_concurrent: {
            uint32_t cc = socksv5_current_connections();
            dlen = sizeof(cc);
            data = malloc(dlen);
            *((uint32_t*)data) = cc;
            numeric_data = true;
            d->status = protocol_status_succeeded;
            break;
        }
        case get_historic: {
            uint32_t hc = socksv5_historic_connections();
            dlen = sizeof(hc);
            data = malloc(dlen);
            *((uint32_t*)data) = hc;
            numeric_data = true;
            d->status = protocol_status_succeeded;
            break;
        }
        case get_transfered: {
            uint32_t bt = socksv5_bytes_transferred();
            dlen = sizeof(bt);
            data = malloc(dlen);
            *((uint32_t*)data) = bt;
            numeric_data = true;
            d->status = protocol_status_succeeded;
            break;
        }
        case get_proxyusers: {
            //Llena un vector de username, el metodo socksv5_get_users retorna la longitud para el dlen y el data se copia con memcpy
            char usernames[MAX_USERS * ADMIN_UNAME_SIZE];
            dlen = socksv5_get_users(usernames);
            data = malloc(dlen);
            memcpy(data, usernames, dlen);
            d->status = protocol_status_succeeded;
            break;
        }
        case pop3disector: {
            //Activa o desactiva del disector
            bool to = d->parser.protocol->data.disector_data_params == disector_on ? true : false;
            socksv5_toggle_disector(to);
            d->status = protocol_status_succeeded;
            break;
        }
        case add_proxyuser: {
            error_response = socksv5_register_user(d->parser.protocol->data.add_proxy_user_param.user, d->parser.protocol->data.add_proxy_user_param.pass);
            d->status = protocol_status_succeeded;
            break;
        }
        case delete_proxyuser: {
            error_response = socksv5_unregister_user(d->parser.protocol->data.user);
            d->status = protocol_status_succeeded;
            break;
        }
        case add_admin: {
            error_response = protocol_register_admin(d->parser.protocol->data.add_admin_user_param.user, d->parser.protocol->data.add_admin_user_param.token);
            d->status = protocol_status_succeeded;
            break;
        }
        case delete_admin: {
            error_response = protocol_unregister_admin(d->parser.protocol->data.user);
            d->status = protocol_status_succeeded;
            break;
        }
        default:
            d->status = protocol_status_invalid_method;
            break;
    }

        

finally:

    if (error_response != 0)
       d->status = protocol_status_invalid_data;

    if (-1 == protocol_marshall(d->wb, d->status, dlen, data, numeric_data))
        abort(); // el buffer tiene que ser mas grande en la variable

    free(data);
}

