#ifndef __clientSock_h_
#define __clientSock_h_

static struct socks5 *socks_init(int client_fd);

void master_socket_passive_accept(struct selector_key *key);

#endif