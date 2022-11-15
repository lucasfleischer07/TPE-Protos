#ifndef TCPSERVERUTIL_H_
#define TCPSERVERUTIL_H_
#define TRUE 1
#include <stdio.h>
#include <sys/socket.h>


int socket_creator(sa_family_t family);

int bind_socket(int server, struct sockaddr *address, socklen_t address_len);

/** creates and binds an IPv4 socket */
int ipv4_socket_binder(struct in_addr bind_address, unsigned port);

/** creates and binds an IPv6 socket */
int ipv6_socket_binder(struct in6_addr bind_address, unsigned port);



#endif 