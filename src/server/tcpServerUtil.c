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
#include "clientSock.h"

#define MAXPENDING 5 // Maximum outstanding connection requests
#define BUFSIZE 256
#define MAX_ADDR_BUFFER 128

static char addrBuffer[MAX_ADDR_BUFFER];






/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
int setupTCPServerSocket(const char *service) {
	// Construct the server address structure
	struct addrinfo addrCriteria;                   // Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;             // Any address family
	addrCriteria.ai_flags = AI_PASSIVE;             // Accept on any address/port
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only stream sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

	int opt = TRUE;

	struct addrinfo *servAddr; 			// List of server addresses
	int rtnVal = getaddrinfo(NULL, service, &addrCriteria, &servAddr);
	if (rtnVal != 0) {
		log(FATAL, "getaddrinfo() failed %s", gai_strerror(rtnVal));
		return -1;
	}

	int servSock = -1;
	// Intentamos ponernos a escuchar en alguno de los puertos asociados al servicio, sin especificar una IP en particular
	// Iteramos y hacemos el bind por alguna de ellas, la primera que funcione, ya sea la general para IPv4 (0.0.0.0) o IPv6 (::/0) .
	// Con esta implementación estaremos escuchando o bien en IPv4 o en IPv6, pero no en ambas
	for (struct addrinfo *addr = servAddr; addr != NULL && servSock == -1; addr = addr->ai_next) {
		errno = 0;
		// Create a TCP socket
		servSock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (servSock < 0) {
			log(DEBUG, "Cant't create socket on %s : %s ", printAddressPort(addr, addrBuffer), strerror(errno));  
			continue;       // Socket creation failed; try next address
		}

		//set master socket to allow multiple connections , this is just a good habit, it will work without this
		if( setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0 )
		{
			perror("setsockopt");
			exit(EXIT_FAILURE);
		}
  

		// Bind to ALL the address and set socket to listen
		if ((bind(servSock, addr->ai_addr, addr->ai_addrlen) == 0) && (listen(servSock, MAXPENDING) == 0)) {
			// Print local address of socket
			struct sockaddr_storage localAddr;
			socklen_t addrSize = sizeof(localAddr);
			if (getsockname(servSock, (struct sockaddr *) &localAddr, &addrSize) >= 0) {
				printSocketAddress((struct sockaddr *) &localAddr, addrBuffer);
				log(INFO, "Binding to %s", addrBuffer);
			}
		} else {
			log(DEBUG, "Cant't bind %s", strerror(errno));  
			close(servSock);  // Close and try with the next one
			servSock = -1;
		}
	}

	freeaddrinfo(servAddr);

	return servSock;
}

int acceptTCPConnection(int servSock) {
	struct sockaddr_storage clntAddr; // Client address
	// Set length of client address structure (in-out parameter)
	socklen_t clntAddrLen = sizeof(clntAddr);

	// Wait for a client to connect
	int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
	if (clntSock < 0) {
		log(ERROR, "accept() failed");
		return -1;
	}

	// clntSock is connected to a client!
	printSocketAddress((struct sockaddr *) &clntAddr, addrBuffer);
	log(INFO, "Handling client %s", addrBuffer);

	return clntSock;
}
/*
int getSpecifiedHost(char* domain, const char *service){
	domain[strlen(domain)-1] = '\0';
	char addrBuffer[MAX_ADDR_BUFFER];
	struct addrinfo addrCriteria;                   // Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_INET;             // v4 or v6 is OK
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only streaming sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

	// Get address(es)
	struct addrinfo *servAddr; // Holder for returned list of server addrs
	
	int rtnVal = getaddrinfo("www.google.com", "8080", &addrCriteria, &servAddr);
	log(INFO, "0. Valor de rtvVal: %d", rtnVal);
	if (rtnVal != 0) {
		log(ERROR, "getaddrinfo() failed %s", gai_strerror(rtnVal))
		return -1;
	}
	log(INFO, "1. Despues del getaddrinfo");
	int sock = -1;
	for (struct addrinfo *addr = servAddr; addr != NULL && sock == -1; addr = addr->ai_next) {
		// Create a reliable, stream socket using TCP
		log(INFO, "2. En el for antes del socket");
		sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		log(INFO, "3. Valor del sock: %d", sock);
		if (sock >= 0) {
			errno = 0;
			log(INFO, "4. If del sock >= 0");
			log(INFO, "4.0.1 ai_next del connect %s", addr->ai_next);
			log(INFO, "4.0.2 ai_addr del connect %d", addr->ai_addr);
			log(INFO, "4.0.3 ai_addrlen del connect %d", addr->ai_addrlen);
			
			// * TODO: VER EL ERROR QUE TIRA ACA, EL ERROR ESTA EN EL LLAMADO A CONNECT PERO NO SABEMOS BIEN PORQUE FALLA
			// Establish the connection to the server
			if ( connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {

				log(INFO, "4.1. Dento del if del connect");
				log(INFO, "can't connectto %s: %s", printAddressPort(addr, addrBuffer), strerror(errno))
				close(sock); 	// Socket connection failed; try next address
				sock = -1;
				log(INFO, "4.2. Saliendo del if del connect");
			} else {
				log(INFO, "5. Encontro sock valido");
			}
			log(INFO, "6. Saliendo del if del sock");
		} else {
			log(DEBUG, "Can't create client socket on %s",printAddressPort(addr, addrBuffer)) 
		}
	}
	log(INFO, "10. Afuera");
	freeaddrinfo(servAddr); 
	return sock;
}
*/
/*
int getRequestedHTML (char* domain){
    char *path = strchr(domain, '/');
	if(path != NULL) {
    	*path++ = '\0';
	}
	
    //printf("host: %s; path: %s\n", domain, path);

    int sock, bytes_recieved;  
    char send_data[1024],recv_data[9999];
	
    if ((sock = getSpecifiedHost(domain,"8080")) == -1){
       perror("Socket");
       return 0;
    }
	
	//llena el buffer con el path pedido
	log(INFO, "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n");
    snprintf(send_data, sizeof(send_data), "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n");
    //snprintf(send_data, sizeof(send_data), "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", path == NULL ? "" : path, domain);
	//printf("%s\n", send_data);

    //Hace el pedido a internet
    send(sock, send_data, strlen(send_data), 0); 
    printf("Data sended.\n");  
    //Espera para recibir la info
    bytes_recieved = recv(sock, recv_data, 9999, 0);
    recv_data[bytes_recieved] = '\0';
    close(sock);
    log(INFO, "Data reveieved.\n");
    log(INFO,"%s\n", recv_data);
    return 1;
}
*/
int handleTCPEchoClient(int clntSocket) {
	char buffer[BUFSIZE]; // Buffer for echo string
	// Receive message from client
	ssize_t numBytesRcvd = recv(clntSocket, buffer, BUFSIZE, 0);
	if (numBytesRcvd < 0) {
		log(ERROR, "recv() failed");
		return -1;   // TODO definir codigos de error
	}
	
	// Send received string and receive again until end of stream
	if (numBytesRcvd == 0) { // 0 indicates end of stream
		return 0;
	}
	
	//Le pongo 0 al final
	buffer[numBytesRcvd*sizeof(char)-1]='\0';
	

	log(INFO, "string received: %s",buffer);
	
	//hace el request del cliente y lo muestra en el server NO EN EL CLIENTE
	//getRequestedHTML(buffer);
	
	ssize_t numBytesSent = send(clntSocket, buffer, numBytesRcvd, 0);
	if (numBytesSent < 0) {
		log(ERROR, "send() failed");
		return -1;   // TODO definir codigos de error
	}
	else if (numBytesSent != numBytesRcvd) {
		log(ERROR, "send() sent unexpected number of bytes ");
		return -1;   // TODO definir codigos de error
	}	
	return 1;
}

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    //done = true;
}

