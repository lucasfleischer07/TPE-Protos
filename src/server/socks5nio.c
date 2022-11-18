/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
#include<stdio.h>
#include <stdlib.h>  
#include <string.h>  
#include <assert.h>  
#include <errno.h>
#include <time.h>
#include <unistd.h>  
#include <pthread.h>

#include <arpa/inet.h>

#include "hello.h"
#include "request.h"
#include "buffer.h"

#include "stm.h"
#include "socks5nio.h"
#include "netutils.h"
#include "auth.h"
#include "disector.h"

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

/** usado por AUTH_READ y AUTH_WRITE */
struct auth_st {
    /** buffer utilizado para I/O */
    buffer                     *rb, *wb;

    /** parser */
    struct auth                auth;
    struct auth_parser         parser;

    /** el resumen de la respuesta a enviar */
    enum auth_response_status  status;

    /** referencia al campo de struct socks5 */
    char                       *uname;
};

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

/** usado por REQUEST_CONNECTING */
struct connecting {
    buffer   *wb;
    int      *origin_fd;
    int      *client_fd;
    enum socks_response_status *status;
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

    /** disector para el uso de pop3*/
    struct disector_parser        dp;

    /** estados para el client_fd */
    union {
        struct hello_st           hello;
        struct auth_st            auth;
        struct request_st         request;
        struct copy               copy;
    } client;
    /** estados para el origin_fd */
    union {
        struct connecting         conn;
        struct copy               copy;
    } orig;

    /** cantidad de referencias a este objeto. si es 1 se debe destruir. */
    unsigned references;

    //los raw_buff son los arreglos utilizados por los buffers, los buffers se encargan del manejo de 
    //indice de escritura,lectura y resets necesarios. Estos se van a usar en todos los estados
    uint8_t raw_buff_a[RAW_BUFFER_SIZE], raw_buff_b[RAW_BUFFER_SIZE];
    buffer read_buffer, write_buffer;

    struct socks5 *next; // siguiente socks5 en la pool
};

/** Estadisticas del servidor proxy*/
uint32_t historic_connections = 0;
uint32_t current_connections  = 0;
uint32_t bytes_transferred    = 0;


/** Pool de structs socks5 para ser reusados */
static const unsigned   max_pool = 50; // tamaño max
static unsigned         pool_size = 0; // tamaño actual
static struct socks5    *pool = 0;     // pool propiamente dicho

bool is_auth_on = true;
size_t registered_users = 0;

bool is_disector_on = true;

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

////////////
//  REQUEST
////////////

/////////////// REQUEST_READ y REQUEST_RESOLVE ///////////////////////////////////

void log_request(enum socks_response_status status, const char *uname, struct request *request, const struct sockaddr *clientaddr, const struct sockaddr* originaddr);
static unsigned request_process(struct selector_key *key, struct request_st *d);
static unsigned request_connect(struct selector_key *key, struct request_st *d);
static void * request_resolv_blocking(void *data);
/** inicializa las variables de los estados REQUEST_ */
static void
request_init(const unsigned state, struct selector_key *key) {
    struct request_st *d    = &ATTACHMENT(key)->client.request;

    d->rb                   = &(ATTACHMENT(key)->read_buffer);
    d->wb                   = &(ATTACHMENT(key)->write_buffer);
    d->parser.request       = &d->request; // inicializa el parser parece
    d->status               = status_general_SOCKS_server_failure;
    request_parser_init(&d->parser);
    d->client_fd            = &ATTACHMENT(key)->client_fd;
    d->origin_fd            = &ATTACHMENT(key)->origin_fd;
    d->origin_addr          = &ATTACHMENT(key)->origin_addr;
    d->origin_addr_len      = &ATTACHMENT(key)->origin_addr_len;
    d->origin_domain        = &ATTACHMENT(key)->origin_domain;
}



/** lee todos los bytes del mensaje de tipo 'request', una vez parseado correctamente
 *  inicia su proceso correspondiente */
static unsigned
request_read(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    buffer *b            = d->rb;
    unsigned ret         = REQUEST_READ;
    bool error           = false;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(b, &count);
    n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(b, n);
        int st = request_consume(b, &d->parser, &error);
        if (!error && request_is_done(st, NULL)){
            ret = request_process(key, d); 
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static unsigned
request_error_write(struct selector_key *key, struct request_st *d, enum socks_response_status status) {
    d->status = status;
    if (-1 == request_marshall(d->wb, d->status)) {
        d->status = status_general_SOCKS_server_failure;
        abort(); // el buffer tiene que ser mas grande en la variable
    }
    selector_status st = selector_set_interest(key->s, ATTACHMENT(key)->client_fd, OP_WRITE);
    return SELECTOR_SUCCESS == st ? REQUEST_WRITE : ERROR;
}


/* Dependiendo del request, ejecuta diferente acciones*/
static unsigned
request_process(struct selector_key *key, struct request_st *d) {
    unsigned ret;
    pthread_t tid;

    switch (d->request.cmd) {
        case socks_req_cmd_connect:
            switch (d->request.dest_addr_type) {
                case socks_req_addrtype_ipv4: {
                    ATTACHMENT(key)->origin_domain = AF_INET;
                    d->request.dest_addr.ipv4.sin_port = d->request.dest_port;
                    ATTACHMENT(key)->origin_addr_len = sizeof(d->request.dest_addr.ipv4);
                    memcpy(&ATTACHMENT(key)->origin_addr, &d->request.dest_addr, sizeof(d->request.dest_addr.ipv4));
                    ret = request_connect(key, d);
                    break;
                }
                case socks_req_addrtype_ipv6: {
                    ATTACHMENT(key)->origin_domain = AF_INET6;
                    d->request.dest_addr.ipv6.sin6_port = d->request.dest_port;
                    ATTACHMENT(key)->origin_addr_len = sizeof(d->request.dest_addr.ipv6);
                    memcpy(&ATTACHMENT(key)->origin_addr, &d->request.dest_addr, sizeof(d->request.dest_addr.ipv6));
                    ret = request_connect(key, d);
                    break;
                }
                case socks_req_addrtype_domain: {
                    struct selector_key *k = malloc(sizeof(*key));
                    if (k == NULL) {
                        ret = request_error_write(key, d, status_general_SOCKS_server_failure);
                    } else {
                        memcpy(k, key, sizeof(*key));
                        // Resolucion de DNS es bloqueante, por lo que se genera un hilo para la operacion
                        if (-1 == pthread_create(&tid, 0, request_resolv_blocking, k)) {
                            ret = request_error_write(key, d, status_general_SOCKS_server_failure);
                            free(k);
                        } else {
                            ret = REQUEST_RESOLV;
                            selector_set_interest_key(key, OP_NOOP);
                        }
                    }
                    break;
                }
                default: {
                    ret = request_error_write(key, d, status_address_type_not_supported);
                }
            }
            break;
        case socks_req_cmd_bind:
        case socks_req_cmd_associate:
        default:
            ret = request_error_write(key, d, status_command_not_supported);
            break;
    }

    return ret;
}




// debe retornar un state
static unsigned
request_connect(struct selector_key *key, struct request_st *d) {
    bool error                        = false;
    int *fd                           = d->origin_fd;
    enum socks_response_status status = d->status;

    // si ya habiamos asignado una vez el fd y estamos tratando de conectarnos con una IP diferente, cerramos el viejo y lo creamos devuelta
    if (ATTACHMENT(key)->stm.current->state == REQUEST_CONNECTING) {
        selector_unregister_fd(key->s, *fd);
        close(*fd);
    }

    *fd = socket(ATTACHMENT(key)->origin_domain, SOCK_STREAM, 0);

    if (*fd == -1) {
        status = status_general_SOCKS_server_failure;
        error = true;
        goto finally;
    }

    if (selector_fd_set_nio(*fd) == -1)
        goto finally;
    
    if (-1 == connect(*fd, (const struct sockaddr *)&ATTACHMENT(key)->origin_addr, ATTACHMENT(key)->origin_addr_len)) {
        if (errno == EINPROGRESS) {
            // es lo esperable, hay que aguardar la conexion
            // dejamos de escuchar del socket del cliente
            selector_status st = selector_set_interest(key->s, ATTACHMENT(key)->client_fd, OP_NOOP);
            if (SELECTOR_SUCCESS != st) {
                error = true;
                goto finally;
            }

            // esperamosla conexion en el nuevo socket
            st = selector_register(key->s, *fd, &socks5_handler, OP_WRITE, key->data);

            if (SELECTOR_SUCCESS != st) {
                error = true;
                goto finally;
            }
            ATTACHMENT(key)->references += 1;
        } else {
            status = errno_to_socks(errno);
            error = true;
            goto finally;
        }
    } else {
        // estamos conectados sin esperar, es imposible
        abort();
    }

finally:
    if (error) {
        if (*fd != -1) {
            close(*fd);
            *fd = -1;
        }
        return request_error_write(key, d, status);
    }

    return REQUEST_CONNECTING;
}

/** Paso final del request, se llama cuando salte el on_block_ready del estado (cuando la consulta DNS traiga la respuesta). */
static unsigned
request_resolv_done(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    struct socks5 *s     = ATTACHMENT(key);

    if (s->origin_resolution == 0)
        return request_error_write(key, d, status_host_unreachable);

    s->origin_resolution_current = s->origin_resolution;
    s->origin_domain = s->origin_resolution->ai_family;
    s->origin_addr_len = s->origin_resolution->ai_addrlen;
    memcpy(&s->origin_addr, s->origin_resolution->ai_addr, s->origin_resolution->ai_addrlen);
    return request_connect(key, d);
}

// Se ejecuta en un hilo aparte,viene de  request_process()
static void *
request_resolv_blocking(void *data) {
    struct selector_key *key = (struct selector_key *) data;
    struct socks5       *s   = ATTACHMENT(key);

    pthread_detach(pthread_self());
    s->origin_resolution = 0;
    struct addrinfo hints = {
        .ai_family      = AF_UNSPEC,    // allow IPv4 or IPv6
        .ai_socktype    = SOCK_STREAM,  // datagram socket
        .ai_flags       = AI_PASSIVE,   // for wildcard IP address
        .ai_protocol    = 0,            // any protocol
        .ai_canonname   = NULL,
        .ai_addr        = NULL,
        .ai_next        = NULL,
    };

    char buff[7];
    snprintf(buff, sizeof(buff), "%d", ntohs(s->client.request.request.dest_port));

    if (getaddrinfo(s->client.request.request.dest_addr.fqdn, buff, &hints, &s->origin_resolution) != 0) {
        s->client.request.status = status_general_SOCKS_server_failure;
        s->origin_resolution = 0;
    }

    selector_notify_block(key->s, key->fd);

    free(data); // era una copia del estado original
    return 0;    
}


static void
request_read_close(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    request_close(&d->parser);
}

///////////////////////////// REQUEST CONNECTING //////////////////////////////////////////

static void
request_connecting_init(const unsigned state, struct selector_key *key) {
    struct connecting *d = &ATTACHMENT(key)->orig.conn;
    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->origin_fd = &ATTACHMENT(key)->origin_fd;
    d->status    = &ATTACHMENT(key)->client.request.status;
    d->wb        = &ATTACHMENT(key)->write_buffer;
}

/** se establece coneccion y se pasa al estado COPY o falla y se pasa al estado DONE/ERROR */
static unsigned
request_connecting(struct selector_key *key) { // key es un origin_fd
    int error;
    socklen_t len = sizeof(error);
    struct socks5 *s     = ATTACHMENT(key);
    struct connecting *d = &s->orig.conn;

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        *d->status = status_general_SOCKS_server_failure;
    } else {
        if (error == 0) {
            *d->status = status_succeeded;
            *d->origin_fd = key->fd;
        } else if (s->client.request.request.dest_addr_type == socks_req_addrtype_domain && s->origin_resolution_current->ai_next != NULL) {
            s->origin_resolution_current = s->origin_resolution_current->ai_next;
            s->origin_domain = s->origin_resolution_current->ai_family;
            s->origin_addr_len = s->origin_resolution_current->ai_addrlen;
            memcpy(&s->origin_addr, s->origin_resolution_current->ai_addr, s->origin_resolution_current->ai_addrlen);
            request_connect(key, &s->client.request);
            return REQUEST_CONNECTING;
        } else {
            *d->status = errno_to_socks(error);
        }
    }

    if (s->client.request.request.dest_addr_type == socks_req_addrtype_domain) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
        s->origin_resolution_current = 0;
    }

    if (-1 == request_marshall(s->client.request.wb, s->client.request.status)) {
        s->client.request.status = status_general_SOCKS_server_failure;
        abort();
    }

    selector_status ss = 0;
    ss |= selector_set_interest(key->s, *d->client_fd, OP_WRITE);
    ss |= selector_set_interest_key(key, OP_NOOP);

    // dependiendo de ss el siguiente estado al que se va
    return SELECTOR_SUCCESS == ss ? REQUEST_WRITE : ERROR;
}

/** escribe todos los bytes de la respuesta al mensaje 'request' */
static unsigned
request_write(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    unsigned ret = REQUEST_WRITE;
    buffer *b    = d->wb;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_read_ptr(b, &count);
    // si estamos aca es porque el select nos desperto y tiene que haber espacio para mandar al menos 1 byte (no puede bloquear)
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(b, n);
        if (!buffer_can_read(b)) {
            if (d->status == status_succeeded) {
                ret = COPY;
                selector_set_interest(key->s, *d->client_fd, OP_READ);
                selector_set_interest(key->s, *d->origin_fd, OP_READ);
                // guardamos estos valores que necesitaremos luego para logear en la etapa posterior
                memcpy(&ATTACHMENT(key)->dest_addr, &ATTACHMENT(key)->client.request.request.dest_addr, sizeof(union socks_addr));
                ATTACHMENT(key)->dest_addr_type = ATTACHMENT(key)->client.request.request.dest_addr_type;
                // aumentamos los stats del servidor
                historic_connections += 1;
                current_connections  += 1;
            } else {
                ret = ERROR;
                selector_set_interest(key->s, *d->client_fd, OP_NOOP);
                if (-1 != *d->origin_fd)
                    selector_set_interest(key->s, *d->origin_fd, OP_NOOP);
            }

            log_request(
                d->status,
                ATTACHMENT(key)->client_uname,
                &ATTACHMENT(key)->client.request.request,
                (const struct sockaddr *) &ATTACHMENT(key)->client_addr,
                (const struct sockaddr *) &ATTACHMENT(key)->origin_addr
            );
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

static unsigned
auth_process(struct selector_key *key, struct auth_st *d) {
    bool authenticated = false;
    
    for (size_t i = 0; i < registered_users; i++) {
        if (strncmp(d->auth.uname, users[i].uname, 0xff) == 0 &&
            strncmp(d->auth.passwd, users[i].passwd, 0xff) == 0) {
            // sets client uname in struct socks5
            ATTACHMENT(key)->client_uname = users[i].uname;
            authenticated = true;
            break;
        }
    }
    d->status = authenticated ? auth_status_succeeded : auth_status_failure;

    if (-1 == auth_marshall(d->wb, d->status))
        abort();

    return AUTH_WRITE;
}



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



////////////
// COPY
/////////// 
void log_credentials(const char *user, const char *pass, const char *uname, enum socks_addr_type addr_type, union socks_addr *addr, const struct sockaddr* originaddr);



/** Inicializa  el campo de copy en la union de client*/
static void copy_init(const unsigned state, struct selector_key *key) {
    struct copy *d = &ATTACHMENT(key)->client.copy;
    d->fd          = &ATTACHMENT(key)->client_fd;
    d->rb          = &ATTACHMENT(key)->read_buffer;
    d->wb          = &ATTACHMENT(key)->write_buffer;
    d->duplex      = OP_READ | OP_WRITE;
    d->other       = &ATTACHMENT(key)->orig.copy;

    d              = &ATTACHMENT(key)->orig.copy;
    d->fd          = &ATTACHMENT(key)->origin_fd;
    d->rb          = &ATTACHMENT(key)->write_buffer;
    d->wb          = &ATTACHMENT(key)->read_buffer;
    d->duplex      = OP_READ | OP_WRITE;
    d->other       = &ATTACHMENT(key)->client.copy;

    // init disector
    disector_parser_init(&ATTACHMENT(key)->dp);
}

/** actualiza los intereses en el selector segun el estado del copy */
static fd_interest
copy_compute_interests(fd_selector s, struct copy *d) {
    fd_interest ret = OP_NOOP;
    if ((d->duplex & OP_READ) && buffer_can_write(d->rb))
        ret |= OP_READ;
    if ((d->duplex & OP_WRITE) && buffer_can_read(d->wb))
        ret |= OP_WRITE;
    if (SELECTOR_SUCCESS != selector_set_interest(s, *d->fd, ret))
        abort();
    return ret;
}

/** dependiendo del caso, devuelve la estrucutura correspondiente (client.copy o orig.copy) */
static struct copy *
copy_ptr(struct selector_key *key) {
    // agarramos cualquiera de los extremos del copy
    struct copy *d = &ATTACHMENT(key)->client.copy;

    if (*d->fd == key->fd) {
        return d;
    }
    else {
        d = d->other; // agarramos el equivocado, retornamos el otro
    }
    return d;
}

/** lee bytes de un socket y los encola para ser escritos en otro socket */
static unsigned copy_r(struct selector_key *key) {
    struct copy *d = copy_ptr(key);

    assert(*d->fd == key->fd);

    size_t size;
    ssize_t n;
    buffer *b   = d->rb;
    unsigned ret = COPY;

    uint8_t *ptr = buffer_write_ptr(b, &size);
    n = recv(key->fd, ptr, size, 0);
    if (n <= 0) {
        shutdown(*d->fd, SHUT_RD); // no leeremos mas de ahi
        d->duplex &= ~OP_READ;
        if (*d->other->fd != -1) {
            shutdown(*d->other->fd, SHUT_WR);
            d->other->duplex &= ~OP_WRITE;
        }
    } else {
        buffer_write_adv(b, n);
    }

    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);

    if (d->duplex == OP_NOOP) {
        ret = DONE;
        current_connections -= 1;
    }

    return ret;
}

/** escribe bytes ya encolados previamente */
static unsigned copy_w(struct selector_key *key) {
    struct copy *d = copy_ptr(key);
    assert(*d->fd == key->fd);

    struct disector_parser *dp = &ATTACHMENT(key)->dp;

    size_t size;
    ssize_t n;
    buffer *b = d->wb;
    unsigned ret = COPY;

    uint8_t *ptr = buffer_read_ptr(b, &size);
    n = send(key->fd, ptr, size, MSG_NOSIGNAL);
    if (n == -1) {
        shutdown(*d->fd, SHUT_WR);
        d->duplex &= ~OP_WRITE;
        if (*d->other->fd != -1) {
            shutdown(*d->other->fd, SHUT_RD);
            d->other->duplex &= ~OP_READ;
        }
    } else {
        // si estamos esperando el usuario y pass, miramos lo que escribe cliente sobre origin, y si estamos esperando la response o que se inicie una conexion POP3, al reves
        if (is_disector_on && dp->state != disector_incompatible
        && ((dp->state < disector_response && dp->state >= disector_user && key->fd == ATTACHMENT(key)->origin_fd)
        || ((dp->state == disector_response || dp->state == disector_wait_pop) && key->fd == ATTACHMENT(key)->client_fd))) {
            const enum disector_state st = disector_consume(dp, ptr, n);
            if (st == disector_done) {
                log_credentials(dp->disector.user,
                    dp->disector.pass,
                    ATTACHMENT(key)->client_uname,
                    ATTACHMENT(key)->dest_addr_type,
                    &ATTACHMENT(key)->dest_addr,
                    (const struct sockaddr *) &ATTACHMENT(key)->origin_addr
                );
                disector_parser_reset(dp);
            }
        }
        buffer_read_adv(b, n);
        bytes_transferred += n;
    }

    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);

    if (d->duplex == OP_NOOP) {
        ret = DONE;
        current_connections -= 1;
    }

    return ret;
}


/** definiciÃ³n de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state            = HELLO_READ,
        .on_arrival       = hello_read_init,
        .on_departure     = hello_read_close,
        .on_read_ready    = hello_read,
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
    {
        .state            = REQUEST_READ,
        .on_arrival       = request_init,
        .on_departure     = request_read_close,
        .on_read_ready    = request_read,
    },
    {
        .state            = REQUEST_RESOLV,
        .on_block_ready   = request_resolv_done,
    },
    {
        .state            = REQUEST_CONNECTING,
        .on_arrival       = request_connecting_init,
        .on_write_ready   = request_connecting,
    },
    {
        .state            = REQUEST_WRITE,
        .on_write_ready   = request_write,
    },
    {
        .state            = COPY,
        .on_arrival       = copy_init,
        .on_read_ready    = copy_r,
        .on_write_ready   = copy_w,
    },
    {
        .state            = DONE,
    },
    {
        .state            = ERROR,
    }
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


// ISO-8601 date, obtengo el date segun Epoch, lo paso a buf y lo printeo con el offset de la zona
static void log_current_local_date(char *buf) {
    time_t rawtime;
    struct tm *ptm;
    if ((rawtime = time(NULL)) != -1 && (ptm = localtime(&rawtime)) != NULL) {
        if (strftime(buf, 50, "%FT%T", ptm) > 0) {
            printf("%s", buf);
            printf("%s", ptm->tm_zone); //indica el offset local con respecto a UTC
        }
        else
            printf("<date error>");
    } else {
        printf("<date error>");
    }
}

// IP/FQDN y puerto origin server (destino)
static void log_destination(char *buf, const struct sockaddr* originaddr, enum socks_addr_type addr_type, union socks_addr *addr) {
    if (addr_type == socks_req_addrtype_domain) {
        in_port_t port = originaddr->sa_family == AF_INET ? ((struct sockaddr_in *) originaddr)->sin_port : ((struct sockaddr_in6 *) originaddr)->sin6_port;
        printf("%s\t%d", addr->fqdn, ntohs(port));
    } else {
        sockaddr_to_human(buf, 50, originaddr);
        printf("%s", buf);
    }
}

/** Registra  el  uso  del  proxy en salida estandar. Una conexión por línea. Los campos de una línea separado por tabs. */
void log_request(enum socks_response_status status, const char *uname, struct request *request, const struct sockaddr *clientaddr, const struct sockaddr* originaddr) {
    char buf[50];
    
    log_current_local_date(buf);
    putchar('\t');

    // username del cliente
    printf("%s", is_auth_on ? uname : "<anonymous>");
    putchar('\t');

    // tipo de registro
    putchar('A');
    putchar('\t');

    // IP y puerto cliente
    sockaddr_to_human(buf, 50, clientaddr);
    printf("%s", buf);
    putchar('\t');

    // IP/FQDN destino
    log_destination(buf, originaddr, request->dest_addr_type, &request->dest_addr);
    putchar('\t');

    // status code socks5
    printf("%d", status);
    putchar('\n');
}

void log_credentials(const char *user, const char *pass, const char *uname, enum socks_addr_type addr_type, union socks_addr *addr, const struct sockaddr* originaddr) {
    char buf[50];

    log_current_local_date(buf);
    putchar('\t');

    // username del cliente
    printf("%s", is_auth_on ? uname : "<anonymous>");
    putchar('\t');

    // tipo de registro
    putchar('P');
    putchar('\t');

    // protocolo sniffeado
    printf("POP3");
    putchar('\t');

    // IP/FQDN destino
    log_destination(buf, originaddr, addr_type, addr);
    putchar('\t');

    // usuario descubierto
    printf("%s", user);
    putchar('\t');

    // contraseña descubierta
    printf("%s", pass);
    putchar('\n');
}
