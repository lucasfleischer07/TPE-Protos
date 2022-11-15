/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
#include<stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <time.h>
#include <unistd.h>  // close
#include <pthread.h>

#include <arpa/inet.h>

#include "hello.h"
#include "request.h"
#include "buffer.h"

#include "stm.h"
#include "socks5nio.h"
#include "netutils.h"
#include "auth.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define RAW_BUFFER_SIZE 1024

/** maquina de estados general */
enum socks_v5state {
    /**
     * recibe el mensaje `hello` del cliente, y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - HELLO_READ  mientras el mensaje no estÃ© completo
     *   - HELLO_WRITE cuando estÃ¡ completo
     *   - ERROR       ante cualquier error (IO/parseo)
     */
    HELLO_READ,

    /**
     * envÃ­a la respuesta del `hello' al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    HELLO_WRITE,

    /**
     * recibe las credenciales (usuario y contraseña, segun RFC 1929) del cliente, e inicia su proceso
     * 
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - AUTH_READ            mientras el mensaje no este completo
     *   - AUTH_WRITE           cuando está completo
     *   - ERROR                ante cualquier error (IO/parseo)
    */
    AUTH_READ,

    /**
     * informa al cliente si la autenticación fue exitosa o no.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - AUTH_WRITE   mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    AUTH_WRITE,

    /**
     * recibe el request del cliente, e inicia su proceso
     * 
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_READ         mientras el mensaje no este completo
     *   - REQUEST_RESOLV       si no requiere resolver un nombre DNS
     *   - REQUEST_CONNECTING   si no requiere resolver DNS y podemos
     *                          iniciar la conexion al origin server
     *   - REQUEST_WRITE        si determinamos que el mensaje no lo 
     *                          podemos procesar (ej: no soportamos el comando)
     *   - ERROR                ante cualquier error (IO/parseo)
    */
    REQUEST_READ,

    /**
     * Espera la resolucion DNS
     * 
     * Intereses:
     *     - OP_NOOP sobre client_fd. Espera un evento de que la tarea 
     *       bloqueante haya terminado
     *
     * Transiciones:
     *   - REQUEST_CONNECTING   si se logra resolucion del nombre y se puede iniciar la conexion al origin server
     *   - REQUEST_WRITE        en otro caso
    */
    REQUEST_RESOLV,

    /**
     * Espera que se establezca la conexion al origin server
     * 
     * Intereses:
     *     - OP_WRITE sobre origin_fd
     *     - OP_NOOP sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_WRITE        se haya logrado o no establecer la conexion
    */
    REQUEST_CONNECTING,

    /**
     * envia la respuesta del request al cliente
     * 
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *     - OP_NOOP sobre origin_fd
     *
     * Transiciones:
     *   - REQUEST_WRITE    mientras quedan bytes por enviar
     *   - COPY             si el request fue exitoso y tenemos que copiar
     *                      el contenido de los fd
     *   - ERROR            ante I/O error
    */
    REQUEST_WRITE,

    /**
     * copia bytes entre client_fd y origin_fd
     * 
     * Intereses: (tanto para client_fd como para origin_fd)
     *     - OP_READ  si hay espacio libre para escribir en el buffer de lectura
     *     - OP_WRITE si hay bytes para leer en el buffer de escritura
     *
     * Transiciones:
     *   - DONE    cuando no queda nada mas por copiar
    */
    COPY,

    // estados terminales, en ambos casos la maquina de estados llama a socksv5_done()
    DONE,
    ERROR,
};

////////////////////////////////////////////////////////////////////
// DefiniciÃ³n de variables para cada estado

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    /** buffer utilizado para I/O */
    buffer               *rb, *wb;
    struct hello_parser   parser;
    /** el mÃ©todo de autenticaciÃ³n seleccionado */
    uint8_t               method;
} ;

struct request_st {
    /** buffer utilizado para I/O */
    buffer                      *rb, *wb;

    /** parser */
    struct request              request;
    struct request_parser       parser;

    /** el resumen de la respuesta a enviar */
    enum socks_response_status  status;

    // referencian a los campos de struct socks5
    struct sockaddr_storage     *origin_addr;
    socklen_t                   *origin_addr_len;
    int                         *origin_domain;

    const int                   *client_fd;
    int                         *origin_fd;
};

/** usado por COPY */
struct copy {
    /** el file descriptor propio (client.copy tiene client_fd y lo mismo orig) */
    int         *fd;
    /** el buffer que se utiliza para hacer la copia */
    buffer      *rb, *wb;
    // seria como el "intereses" de este extremo del copy, teniendo prendidos 1 o varios de los bits de OP_READ, OP_WRITE y OP_NOOP. Sirve para cerrar la escritura o la lectura.
    fd_interest duplex;
    struct copy *other; // el otro extremo del copy
};

/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una Ãºnica
 * alocaciÃ³n cuando recibimos la conexiÃ³n.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks5 {

    /** informacion del cliente */
    int                           client_fd;
    struct sockaddr_storage       client_addr; // direccion IP
    socklen_t                     client_addr_len; // tamaño de IP (v4 o v6)
    char                          *client_uname;

    /** resolucion DNS de la direc del origin server */
    struct addrinfo               *origin_resolution;
    /** intento actual de la direccion del origin server */
    struct addrinfo               *origin_resolution_current;

    /** informacion del origin server requerido por el cliente*/
    int                           origin_fd;
    struct sockaddr_storage       origin_addr;
    socklen_t                     origin_addr_len;
    int                           origin_domain;
    enum    socks_addr_type       dest_addr_type;
    union   socks_addr            dest_addr;

    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    union {
        struct hello_st           hello;
        struct request_st         request;
        struct copy               copy;
    } client;
    /** estados para el origin_fd */
    /*union {
        struct connecting         conn;
        struct copy               copy;
    } orig;*/

    /** cantidad de referencias a este objeto. si es 1 se debe destruir. */
    unsigned references;

    //los raw_buff son los arreglos utilizados por los buffers, los buffers se encargan del manejo de 
    //indice de escritura,lectura y resets necesarios. Estos se van a usar en todos los estados
    uint8_t raw_buff_a[RAW_BUFFER_SIZE], raw_buff_b[RAW_BUFFER_SIZE];
    buffer read_buffer, write_buffer;

    struct socks5 *next; // siguiente socks5 en la pool
};

/** Pool de structs socks5 para ser reusados */
static const unsigned   max_pool = 50; // tamaño max
static unsigned         pool_size = 0; // tamaño actual
static struct socks5    *pool = 0;     // pool propiamente dicho

bool is_auth_on = true;
size_t registered_users = 0;


static const struct state_definition * socks5_describe_states(void);

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexiÃ³n pasiva.
// son los que emiten los eventos a la maquina de estados.
static void socksv5_done(struct selector_key* key);

static unsigned auth_process(struct selector_key *key, struct auth_st *d);

static struct socks5 *socks5_new(int client_fd) {
    struct socks5 *ret;

    if (pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret = pool;
        pool = pool->next;
        ret->next = 0; // lo sacamos de la pool para retornarlo y usarlo
    }

    if (ret == NULL)
        goto finally;
    
    memset(ret, 0x00, sizeof(*ret)); // inicializamos en 0 todo

    ret->origin_fd = -1;
    ret->client_fd = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);

    ret->stm.initial = HELLO_READ;
    ret->stm.max_state = ERROR;
    ret->stm.states = socks5_describe_states();
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);

    ret->references = 1;

finally:
    return ret;
}

/** realmente destruye */
static void
socks5_destroy_(struct socks5* s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
socks5_destroy(struct socks5 *s) {
    if(s == NULL) {
        // nada para hacer
    } else if(s->references == 1) {
        if(s != NULL) {
            if(pool_size < max_pool) {
                s->next = pool;
                pool    = s;
                pool_size++;
            } else {
                socks5_destroy_(s);
            }
        }
    } else {
        s->references -= 1;
    }
}

void
socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    }
}

/** obtiene el struct (socks5 *) desde la llave de selecciÃ³n  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

/* declaraciÃ³n forward de los handlers de selecciÃ³n de una conexiÃ³n
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read   (struct selector_key *key);
static void socksv5_write  (struct selector_key *key);
static void socksv5_block  (struct selector_key *key);
static void socksv5_close  (struct selector_key *key);
static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};

/** Intenta aceptar la nueva conexiÃ³n entrante*/
void
socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct socks5                *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_addr,
                                                          &client_addr_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = socks5_new(client);
    if(state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberÃ³ alguna conexiÃ³n.
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

////////////////////////////////////////////////////////////////////////////////
// HELLO
////////////////////////////////////////////////////////////////////////////////
bool is_auth_on = true;

/** callback del parser utilizado en `read_hello' */
static void
on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected  = p->data;

    if(SOCKS_HELLO_NO_AUTHENTICATION_REQUIRED == method) {
       *selected = method;
    }
}

/** inicializa las variables de los estados HELLO_â€¦ */
static void
hello_read_init(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    d->rb                              = &(ATTACHMENT(key)->read_buffer);
    d->wb                              = &(ATTACHMENT(key)->write_buffer);
    d->parser.data                     = &d->method;
    d->parser.on_authentication_method = on_hello_method, hello_parser_init(
            &d->parser);
    if (registered_users == 0)
        is_auth_on = false; // turn off authentication method
}

/** libera los recursos al salir de HELLO_READ */
static void
hello_read_close(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    hello_parser_close(&d->parser);
}

static unsigned
hello_process(const struct hello_st* d);

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned
hello_read(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned  ret      = HELLO_READ;
        bool  error    = false;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n > 0) {
        buffer_write_adv(d->rb, n);
        const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
        if(hello_is_done(st, 0)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = hello_process(d);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

/** procesamiento del mensaje `hello' */
static unsigned
hello_process(const struct hello_st* d) {
    unsigned ret = HELLO_WRITE;

    uint8_t m = d->method;
    const uint8_t r = (m == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) ? 0xFF : 0x00;
    if (-1 == hello_marshall(d->wb, r)) {
        ret  = ERROR;
    }
    if (SOCKS_HELLO_NO_ACCEPTABLE_METHODS == m) {
        ret  = ERROR;
    }
    return ret;
}

static unsigned
hello_write(struct selector_key *key) { // key corresponde a un client_fd
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    unsigned ret       = HELLO_WRITE;
    uint8_t  *ptr;
    size_t   count;
    ssize_t  n;
    
    ptr = buffer_read_ptr(d->wb, &count);
    // esto deberia llamarse cuando el select lo despierta y sabe que se puede escribir al menos 1 byte, por eso no checkeamos el EWOULDBLOCK
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(d->wb, n);
        // si terminamos de mandar toda la response del HELLO, hacemos transicion HELLO_WRITE -> AUTH_READ o HELLO_WRITE -> REQUEST_READ
        if (!buffer_can_read(d->wb)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
                // en caso de que haya fallado el handshake del hello, el cliente es el que cerrara la conexion
                ret = is_auth_on ? AUTH_READ : REQUEST_READ;
            } else {
                ret = ERROR;
            }
        }
    }

    return ret;
}

static void
auth_init(const unsigned state, struct selector_key *key) {
    struct auth_st *d       = &ATTACHMENT(key)->client.auth;
    d->rb                   = &(ATTACHMENT(key)->read_buffer);
    d->wb                   = &(ATTACHMENT(key)->write_buffer);
    d->parser.auth          = &d->auth;
    d->status               = auth_status_failure;
    auth_parser_init(&d->parser);
    d->uname                = ATTACHMENT(key)->client_uname;
}

/** lee la auth e inicia el proceso */
static unsigned
auth_read(struct selector_key *key) {
    struct auth_st *d       = &ATTACHMENT(key)->client.auth;

    buffer *b            = d->rb;
    unsigned ret         = AUTH_READ;
    bool error           = false;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(b, &count);
    n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(b, n);
        int st = auth_consume(b, &d->parser, &error);
        if (auth_is_done(st, 0)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = auth_process(key, d);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static unsigned
auth_write(struct selector_key *key) {
    struct auth_st *d       = &ATTACHMENT(key)->client.auth;
    unsigned ret            = AUTH_WRITE;
    buffer *b               = d->wb;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_read_ptr(b, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(b, n);
        if (!buffer_can_read(b)) {
            if (d->status == auth_status_succeeded) {
                if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ))
                    ret = REQUEST_READ;
                else
                    ret = ERROR;
            } else {
                // close conection
                ret = ERROR;
                selector_set_interest_key(key, OP_NOOP);
            }
            
        }
    }

    return ret;
}

////////////
// AUTH
/////////// 

struct user {
    char    uname[0xff];    // null terminated
    char    passwd[0xff];   // null terminated
};

struct user users[MAX_USERS];

int socksv5_register_user(char *uname, char *passwd) {
    if (registered_users >= MAX_USERS)
        return 1; // maximo numero de usuarios alcanzado
    
    for (size_t i = 0; i < registered_users; i++) {
        if (strcmp(uname, users[i].uname) == 0)
            return -1; // username ya existente
    }

    // insertamos al final (podrian insertarse en orden alfabetico para mas eficiencia pero al ser pocos es irrelevante)
    strncpy(users[registered_users].uname, uname, 0xff);
    strncpy(users[registered_users++].passwd, passwd, 0xff);
    return 0;
}

void socksv5_toggle_disector(bool to) {
    is_disector_on = to;
}

/** definiciÃ³n de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state            = HELLO_READ,
        .on_arrival       = hello_read_init,
        .on_departure     = hello_read_close,
        .on_read_ready    = hello_re    ad,
    },
    {
        .state            = HELLO_WRITE,
        .on_write_ready   = hello_write,
    },
    {
        .state            = AUTH_READ,
        .on_arrival       = auth_init,
        .on_read_ready    = auth_read,
    },
    {
        .state            = AUTH_WRITE,
        .on_write_ready   = auth_write,
    },
};


static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void
socksv5_done(struct selector_key* key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for(unsigned i = 0; i < N(fds); i++) {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}

static const struct state_definition * socks5_describe_states(void){
    return client_statbl;
}