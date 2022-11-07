#ifndef TCPSERVERUTIL_H_
#define TCPSERVERUTIL_H_
#define TRUE 1
#include <stdio.h>
#include <sys/socket.h>


// Create, bind, and listen a new TCP server socket
int setupTCPServerSocket(const char *service);

// Accept a new TCP connection on a server socket
int acceptTCPConnection(int servSock);

// Handle new TCP client
int handleTCPEchoClient(int clntSocket);

// Makes the HTML request from the client
int getRequestedHTML (char* domain);

static void sigterm_handler(const int signal);

#endif 