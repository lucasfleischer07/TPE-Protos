#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "buffer.h"
#include "stm.h"
#include "parser.h"
#include "request.h"
#include "selector.h"
#define  BUFFER_MAX_SIZE 1024


/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks {
    
    /** informacion del cliente */
    int                           client_fd;
    struct sockaddr_storage       client_addr; // direccion IP
    socklen_t                     client_addr_len; // tamaño de IP (v4 o v6)
    char                          *client_uname;

    /** resolucion DNS de la direc del origin server */
    struct addrinfo               *origin_resolution;
    /** intento actual de la direccion del origin server */
    struct addrinfo               *origin_resolution_current;

    /** informacion del origin server */
    int                           origin_fd;
    struct sockaddr_storage       origin_addr;
    socklen_t                     origin_addr_len;
    int                           origin_domain;
    enum    socks_addr_type       dest_addr_type;
    union   socks_addr            dest_addr;

    /** maquinas de estados */
    struct state_machine          stm;

    //buffers usados en los estados
    uint8_t * read_buffer_array[BUFFER_MAX_SIZE],write_buffer_array[BUFFER_MAX_SIZE];
    buffer read_buffer;
    buffer write_buffer;

    /** cantidad de referencias a este objeto. si es 1 se debe destruir. */
    unsigned references;

    struct socks *next; // siguiente en la pool
};

static void socks_read   (struct selector_key *key);
static void socks_write  (struct selector_key *key);
static void socks_block  (struct selector_key *key);
static void socks_close  (struct selector_key *key);

static const struct fd_handler client_sock_handler = {
    .handle_read   = socks_read,
    .handle_write  = socks_write,
    .handle_close  = socks_close,
    .handle_block  = socks_block,
};

//SIN USO DE LA STM POR AHORA
static void
socks_read(struct selector_key *key) {
    struct socks * sockData   = ((struct socks *)key->data);
    // Receive the bytes into the client's buffer.
    size_t max_write_available;
    uint8_t * write_ptr = buffer_write_ptr(&sockData->write_buffer,&max_write_available);
    ssize_t received = recv(key->fd, write_ptr , max_write_available, 0);
    if (received <= 0) { 
        printf("recv() returned %ld, closing client %d\n", received, key->fd);
        selector_unregister_fd(key->s, key->fd);
        return;
    }
    buffer_write_adv(&sockData->write_buffer, received);

    //Ahora lo suscribo para lectura
    fd_interest newInterests = OP_WRITE;
    if (buffer_can_write(&sockData->write_buffer))
        newInterests |= OP_READ;
    
    // Update the interests in the selector.
    selector_set_interest_key(key, newInterests);
}

static void
socks_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socks_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socks_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

/** lista de socks  */
static const unsigned   max_pool = 50; // tamaño max
static unsigned         pool_size = 0; // tamaño actual
static struct socks    *pool = 0;      // pool propiamente dicho

/** Intenta aceptar la nueva conexión entrante*/
void
master_socket_passive_accept(struct selector_key *key) {
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct socks                  *newSock           = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_addr, &client_addr_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }

	// instancio estructura de estado
	newSock = sock_init(client);

    if(newSock == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memcpy(&(newSock->client_addr), &client_addr, client_addr_len);
    newSock->client_addr_len = client_addr_len;


    // handlers default que avanzan la maquina de estados, nos registramos para lectura esperando el HELLO_READ.
    // Los handlers particulares de cada estado se definen en los hooks del estado particular (struct state_definition)
    if(SELECTOR_SUCCESS != selector_register(key->s, client, &client_sock_handler,
                                              OP_READ, newSock)) {
        goto fail;
    }
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    socks5_destroy(state);
}


static struct socks *socks_init(int client_fd) {
    struct socks *ret;

    //Primer socket que se conecta
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

    //seteo de la smt, hacerlo en el futuro
    //ret->stm.initial = HELLO_READ;
    //ret->stm.max_state = ERROR;
    //ret->stm.states = socks5_describe_states();
    //stm_init(&ret->stm);

    buffer_init(&ret->read_buffer, N(ret->read_buffer_array), ret->read_buffer_array);
    buffer_init(&ret->write_buffer, N(ret->write_buffer_array), ret->write_buffer_array);

    ret->references = 1;

finally:
    return ret;
}