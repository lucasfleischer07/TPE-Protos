#ifndef TCPCLIENT_H_
#define TCPCLIENT_H_

#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>

// Create and connect a new TCP client socket
int tcpClientSocket(const char *server, const char *service);

#endif 