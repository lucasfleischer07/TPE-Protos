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

/** destruye un  `struct connection', tiene en cuenta el pool de objetos.*/
static void connection_destroy(struct connection *s) {
    if(s == NULL) return;

    if(pool_size < max_pool) { // agregamos a la pool
        s->next = pool;
        pool    = s;
        pool_size++;
    } else {
        free(s);    // realmente destruye
    }
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
static void protocol_write  (struct selector_key *key);
static void protocol_close  (struct selector_key *key);

static const struct fd_handler protocol_handler = {
    .handle_read   = protocol_read,  // selector despierta para lectura
    .handle_write  = protocol_write, // selector despierta para escritura
    .handle_close  = protocol_close, // se llama en el selector_unregister_fd
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

//Struct de admin y el arreglo con los admins registrados (aclarando el default)
struct admin {
    char    uname[ADMIN_UNAME_SIZE];    // null terminated
    char    token[ADMIN_TOKEN_SIZE];    // 16 bytes fijos + \0
};

/** el admins[0] sera creado apenas se corra el servidor, pasando el token con el parametro adecuado */
struct admin admins[MAX_ADMINS]; // TODO: agregar admin root desde el server.c
size_t registered_admins = 0;
char *default_admin_uname = "root";
char *default_admin_token = "roottokenspecial";

/** Intenta de registrar el admin pedido, puede fallar por estar al maximo, por que el token sea incorrecto
 *  o por que ese token ya estaba registrado
 */
int protocol_register_admin(char *uname, char *token) { // ambos null terminated
    if (registered_admins >= MAX_ADMINS)
        return 1; // maximo numero de usuarios alcanzado
    
    if (strlen(token) != 0x10)
        return -1; // token invalido

    for (size_t i = 0; i < registered_admins; i++) {
        if (strcmp(uname, admins[i].uname) == 0)
            return -1; // username ya existente
    }
    
    if(strcmp(uname,default_admin_uname) == 0){
        return -1;
    }
    // insertamos al final (podrian insertarse en orden alfabetico para mas eficiencia pero al ser pocos es irrelevante)
    strncpy(admins[registered_admins].uname, uname, ADMIN_UNAME_SIZE - 1);
    strncpy(admins[registered_admins++].token, token, ADMIN_TOKEN_SIZE - 1);
    return 0;
}


/** Intenta borrar el admin de la lista, si es el admin root, falla. Tambien puede fallar si el token 
 *  no esta registrado en la lista
  */
int protocol_unregister_admin(char *uname) {
    if (strcmp(default_admin_uname, uname) == 0)
        return -1; // no se puede remover el admin root

    for (size_t i = 1; i < registered_admins; i++) {
        if (strcmp(uname, admins[i].uname) == 0) {
            // movemos los elementos para tapar el hueco que pudo haber quedado
            if (i + 1 < registered_admins)
                memmove(&admins[i], &admins[i+1], sizeof(struct admin) * (registered_admins - (i + 1)));
            registered_admins--;
            return 0;
        }
    }
    return -1;  // usuario no encontrado
}


static bool protocol_user_is_admin(char *token) {
    if(strncmp(token,default_admin_token, ADMIN_TOKEN_SIZE -1) == 0){
        return true;
    }
    for (size_t i = 0; i < registered_admins; i++) {
        if (strncmp(token, admins[i].token, ADMIN_TOKEN_SIZE -1) == 0)
            return true;
    }
    return false;
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

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// write_handler

static void protocol_write(struct selector_key *key) {
    struct protocol_st *d = &ATTACHMENT(key)->request;

    buffer *b    = d->wb;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_read_ptr(b, &count);
    // como nos desperto el select, al menos 1 byte tenemos que poder mandar
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (n == -1) {
        protocol_finish(key);
    } else {
        buffer_read_adv(b, n);
        //Si no queda nada en el buffer de escritura, el protocolo finaliza correctamente
        if (!buffer_can_read(b))
            protocol_finish(key); // terminamos de escribir, cerramos la conexion
    }
}



/** Handler de la nueva conexion por el protocolo*/
void protocol_passive_accept(struct selector_key *key) {
    struct connection *state = NULL;

    const int client = accept(key->fd, NULL, NULL);

    if (client == -1 || selector_fd_set_nio(client) == -1)
        goto fail;

    // instancio estructura de estado
    state = connection_new(client);
    if (state == NULL)
        goto fail;

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &protocol_handler, OP_READ, state))
        goto fail;

    protocol_init(state);

    return;

fail:
    if (client != -1)
        close(client);

    connection_destroy(state);
}

/*Finaliza la coneccion,ya se por error o no*/
static void protocol_finish(struct selector_key* key) {
    int client_fd = ATTACHMENT(key)->client_fd;
    if (client_fd != -1) {
        if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, client_fd)) // desencadena el protocol_close()
            abort();
        close(client_fd);
    }
}


static void
protocol_close(struct selector_key *key) {
    connection_destroy(ATTACHMENT(key));
}
