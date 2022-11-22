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
#include "socks5nio.h"
#include "args.h"
#include "protocolnio.h"

static bool ended = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, closing everything and ending\n",signal);
    ended = true;
}

static const int FD_UNUSED = -1;
#define IS_FD_USED(fd) ((FD_UNUSED != fd))

int main(int argc, char *argv[]) {
    
    int ret = 0;
    fd_selector selector      = NULL;
    selector_status ss        = SELECTOR_SUCCESS;
    const char* err_msg       = NULL;

    struct socks5args args;
    parse_args(argc, argv, &args);

    // Cierro la entrada standard ya que no es utilizada
    close(0);


    struct in_addr server_ipv4_addr, protocol_ipv4_addr;
    int server_v4 = FD_UNUSED, protocol_v4 = FD_UNUSED;

    struct in6_addr server_ipv6_addr, protocol_ipv6_addr;
    int server_v6 = FD_UNUSED, protocol_v6 = FD_UNUSED;

    

    // sockets pasivos de IPV4 y IPv6 
    if(inet_pton(AF_INET, args.socks_addr, &server_ipv4_addr) == 1){       // if parsing to ipv4 succeded
        server_v4 = ipv4_socket_binder(server_ipv4_addr, args.socks_port);
        if (server_v4 < 0) {
            err_msg = "creation of socket IPV4 failed";
            goto finally;
        }
        fprintf(stdout, "Socks: listening on IPv4 TCP port %d\n", args.socks_port);
    }

    // socket pasivo protocolo IPv4
    if(inet_pton(AF_INET, args.mng_addr, &protocol_ipv4_addr) == 1) {
        protocol_v4 = ipv4_socket_binder(protocol_ipv4_addr, args.mng_port);
        if (protocol_v4 < 0) {
            err_msg = "unable to create IPv4 protocol socket";
            goto finally;
        }
        fprintf(stdout, "Protocol: listening on IPv4 TCP port %d\n", args.mng_port);
    }


    char* ipv6_addr_text = args.is_default_socks_addr ? DEFAULT_SOCKET_ADDR_V6 : args.socks_addr;

    if((!IS_FD_USED(server_v4) || args.is_default_socks_addr) && (inet_pton(AF_INET6, ipv6_addr_text, &server_ipv6_addr) == 1)){
        server_v6 = ipv6_socket_binder(server_ipv6_addr, args.socks_port);
        if (server_v6 < 0) {
            err_msg = "Unable to create IPv6 socket";
            goto finally;
        }
        fprintf(stdout, "Socks: listening on IPv6 TCP port %d\n", args.socks_port);
    }

     // socket pasivo protocol  IPv6
     ipv6_addr_text = args.is_default_mng_addr ? DEFAULT_CONF_ADDR_V6 : args.mng_addr;

    if((!IS_FD_USED(protocol_v4) || args.is_default_mng_addr) && (inet_pton(AF_INET6, ipv6_addr_text, &protocol_ipv6_addr) == 1)){
        protocol_v6 = ipv6_socket_binder(protocol_ipv6_addr, args.mng_port);
        if (protocol_v6 < 0) {
            err_msg = "Unable to create IPv6 socket";
            goto finally;
        }
        fprintf(stdout, "Protocol: listening on IPv6 TCP port %d\n", args.mng_port);
    }
    

    if(!IS_FD_USED(server_v4) && !IS_FD_USED(server_v6)) {
        fprintf(stderr, "Unable to parse socks server ip\n");
        goto finally;
    }

    if(!IS_FD_USED(protocol_v4) && !IS_FD_USED(protocol_v6)) {
        fprintf(stderr, "Unable to parse protocol server ip\n");
        goto finally;
    }

    //Para menejar la finalizacion del servidor, con CNTRL+c salte la sigterm_handler
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    // seteamos los sockets pasivos como no bloqueantes
    if(IS_FD_USED(server_v4) && (selector_fd_set_nio(server_v4) == -1)){
        err_msg = "getting socks server ipv4 socket flags";
        goto finally;
    }

    if(IS_FD_USED(server_v6) && (selector_fd_set_nio(server_v6) == -1)) {
        err_msg = "getting socks server ipv6 socket flags";
        goto finally;
    }

    if(IS_FD_USED(protocol_v4) && (selector_fd_set_nio(protocol_v4) == -1)){
        err_msg = "getting protocol server ipv4 socket flags";
        goto finally;
    }

    if(IS_FD_USED(protocol_v6) && (selector_fd_set_nio(protocol_v6) == -1)) {
        err_msg = "getting protocol server ipv6 socket flags";
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

    const struct fd_handler protocol = {
        .handle_read       = protocol_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL,
    };

    if(IS_FD_USED(protocol_v4)){
        ss = selector_register(selector, protocol_v4, &protocol, OP_READ, NULL);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "registering IPv4 protocol fd";
            goto finally;
        }
    }
    if(IS_FD_USED(protocol_v6)){
        ss = selector_register(selector, protocol_v6, &protocol, OP_READ, NULL);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "registering IPv6 protocol fd";
            goto finally;
        }
    }

    if (ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }

    // Se registran los usuarios del proxy
    for (int i = 0; i < MAX_USERS && args.users[i].name != NULL; i++) {
        int register_status = socksv5_register_user(args.users[i].name, args.users[i].pass);
        if (register_status == -1)
            fprintf(stderr, "User already exists: %s\n", args.users[i].name);
        else if (register_status == 1)
            fprintf(stderr, "Maximum number of users reached\n");
    }

    if (!args.disectors_enabled){
        socksv5_toggle_disector(false);
    }


	while (!ended) { //  Run hasta que salte la sigterm
		err_msg = NULL;
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
	}

    if(err_msg == NULL) {
        err_msg = "closing without error";
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


    if (server_v4 >= 0)
        close(server_v4);
    if(server_v6 >= 0)
        close(server_v6);
    return ret;
}
