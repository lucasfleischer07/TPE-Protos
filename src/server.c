#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros
#include "logger.h"
#include "tcpServerUtil.h"
#include "signal.h"
#include "selector.h"
#include "clientSock.h"

static bool ended = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    ended = true;
}

int main(int argc, char *argv[]) {
	int master_socket , addrlen ;
    fd_selector selector      = NULL;
    int ret = 0;
    selector_status ss = SELECTOR_SUCCESS;
    const char* err_msg = NULL;
	//a message
    char *message = "Welocme to ECHO \r\n";
	fd_set readfds;
	if (argc != 2) {
		log(FATAL, "usage: %s <Server Port>", argv[0]);
	}

	char * servPort = argv[1];

	master_socket = setupTCPServerSocket(servPort);
	if (master_socket < 0){
		return 1;
	}

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);


     // seteamos los sockets pasivos como no bloqueantes
    if(selector_fd_set_nio(master_socket) == -1){
        log(FATAL, "getting socks server ipv4 socket flags");
        goto finally;
    }

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec = 10,
            .tv_nsec = 0,
        },
    };

    if(0 != selector_init(&conf)) {
        log(FATAL, "initializing selector");
        //err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024); // initial elements

	if(selector == NULL) {
        log(FATAL, "unable to create selector");
        goto finally;
    }

    const struct fd_handler master_socket_handler = {
        .handle_read       = master_socket_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };

    ss = selector_register(selector, master_socket, &master_socket_handler, OP_READ, NULL);

    if (ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }
	addrlen = sizeof(struct sockaddr_in);


	while (!ended) { // Run forever
		err_msg = NULL;
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
	}
    finally:
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "" : err_msg,
                ss == SELECTOR_IO
                    ? strerror(errno)
                    : selector_error(ss));
        ret = 2;
    } else if (err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();
    close(master_socket);
    return ret;
}