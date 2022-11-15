#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "logger.h"
#include "util.h"
#include "tcpServerUtil.h"
#include "selector.h"






int
socket_creator(sa_family_t family) {
    const int s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) {
        fprintf(stderr, "unable to create socket\n");
        return -1;
    }

    int sock_optval[] = { 1 }; //  valor de SO_REUSEADDR
    socklen_t sock_optlen = sizeof(int);
    // man 7 ip. no importa reportar nada si falla.
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void*)sock_optval, sock_optlen);
    return s;
}

int
bind_socket(int server, struct sockaddr *address, socklen_t address_len) {
    if (bind(server, address, address_len) < 0) {
        fprintf(stderr, "unable to bind socket\n");
        return -1;
    }

    if (listen(server, 5) < 0) {
        fprintf(stderr, "unable to listen on socket\n");
        return -1;
    }

    return 0;
}


int
ipv4_socket_binder(struct in_addr bind_address, unsigned port) {
    const int server = socket_creator(AF_INET);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr        = bind_address;
    addr.sin_port        = htons(port); // htons translates a short integer from host byte order to network byte order.

    if (bind_socket(server, (struct sockaddr*) &addr, sizeof(addr)) == -1)
        return -1;

    return server;
}

/** creates and binds an IPv6 socket */
int
ipv6_socket_binder(struct in6_addr bind_address, unsigned port) {
    const int server = socket_creator(AF_INET6);
    setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int)); // man ipv6, si falla fallara el bind

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family      = AF_INET6;
    addr.sin6_addr        = bind_address;
    addr.sin6_port        = htons(port); // htons translates a short integer from host byte order to network byte order.

    if (bind_socket(server, (struct sockaddr*) &addr, sizeof(addr)) == -1)
        return -1;

    return server;
}




