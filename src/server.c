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
	fd_set readfds;

	char * servPort = argv[1];

    struct in_addr server_ipv4_addr, monitor_ipv4_addr;
    int server_v4 = FD_UNUSED, monitor_v4 = FD_UNUSED;

    struct in6_addr server_ipv6_addr, monitor_ipv6_addr;
    int server_v6 = FD_UNUSED, monitor_v6 = FD_UNUSED;

    // sockets pasivos de IPV4 y IPv6 
    if(inet_pton(AF_INET, args.socks_addr, &server_ipv4_addr) == 1){       // if parsing to ipv4 succeded
        server_v4 = bind_ipv4_socket(server_ipv4_addr, args.socks_port);
        if (server_v4 < 0) {
            err_msg = "creation of socket IPV4 failed";
            goto finally;
        }
        fprintf(stdout, "Socks: listening on IPv4 TCP port %d\n", args.socks_port);
    }

    char* ipv6_addr_text = args.is_default_socks_addr ? DEFAULT_SOCKS_ADDR_V6 : args.socks_addr;

    if((!IS_FD_USED(server_v4) || args.is_default_socks_addr) && (inet_pton(AF_INET6, ipv6_addr_text, &server_ipv6_addr) == 1)){
        server_v6 = bind_ipv6_socket(server_ipv6_addr, args.socks_port);
        if (server_v6 < 0) {
            err_msg = "creation of socket IPV6 failed";
            goto finally;
        }
        fprintf(stdout, "Socks: listening on IPv6 TCP port %d\n", args.socks_port);
    }

    if(!IS_FD_USED(server_v4) && !IS_FD_USED(server_v6)) {
        fprintf(stderr, "unable to parse socks server ip\n");
        goto finally;
    }

    // seteamos los sockets pasivos como no bloqueantes
    if(IS_FD_USED(server_v4) && (selector_fd_set_nio(server_v4) == -1)){
        err_msg = "getting socks server ipv4 socket flags";
        goto finally;
    }

    if(IS_FD_USED(server_v6) && (selector_fd_set_nio(server_v6) == -1)) {
        err_msg = "getting socks server ipv6 socket flags";
        goto finally;
    }

    const struct selector_init conf = {
        .signal = SIGALRM, // le doy una señal para que trabaje internamente el selector
        .select_timeout = { // estructura para el tiempo maximo de bloqueo
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };

    if(0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024); // initial elements

	if(selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }

    const struct fd_handler master_socket_handler = {
        .handle_read       = socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };

     if(IS_FD_USED(server_v4)){
        ss = selector_register(selector, server_v4, &master_socket_handler, OP_READ, NULL);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "registering IPv4 socks fd";
            goto finally;
        }
    }
    if(IS_FD_USED(server_v6)){
        ss = selector_register(selector, server_v6, &master_socket_handler, OP_READ, NULL);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "registering IPv6 socks fd";
            goto finally;
        }
    }

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