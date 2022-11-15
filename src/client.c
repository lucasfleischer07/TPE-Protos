#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "logger.h"
#include "tcpClientUtil.h"

#define BUFSIZE 512
#define STDIN 0
#define TRUE 1

int main(int argc, char *argv[]) {

	if (argc != 3) {
		log(FATAL, "usage: %s <Server Name/Address> <Server Port/Name>", argv[0]);
	}

	char *server = argv[1];     // First arg: server name IP address 

	// Third arg server port
	char * port = argv[2];

	// Create a reliable, stream socket using TCP
	int sock = tcpClientSocket(server, port);
	if (sock < 0) {
		log(FATAL, "socket() failed")
	}
	

	char * echoString = (char*) malloc(sizeof(char)*BUFSIZE);
	size_t echoStringLen;
	
	while(TRUE) {

		// escribe en echoString lo q leyo en STDIN si no hubo error.   
		// fgets() returns s on success, and NULL on error or when end of file occurs while no characters have been read.
		if(fgets(echoString, BUFSIZE, stdin) == NULL){
			log(FATAL, "fgets error");
		} 
		
		echoStringLen = strlen(echoString); // Determine input length
		if(strcmp(echoString, "exit\n") == 0) {
			break;
		}

		// Send the string to the server
		ssize_t numBytes = send(sock, echoString, echoStringLen, 0);
		if (numBytes < 0 || numBytes != echoStringLen){
			log(FATAL, "send() failed expected %zu sent %zu", echoStringLen, numBytes);
		}
		
		// Receive the same string back from the server
		//unsigned int totalBytesRcvd = 0; 	// Count of total bytes received
		//log(INFO, "Received: ")     		// Setup to print the echoed string
		/*while (totalBytesRcvd < echoStringLen && numBytes >0) {
			char buffer[BUFSIZE]; 
			
			/* Receive up to the buffer size (minus 1 to leave space for a null terminator) bytes from the sender 
			numBytes = recv(sock, buffer, BUFSIZE - 1, 0);
			if (numBytes < 0) {
				log(ERROR, "recv() failed")
			} else if (numBytes == 0) {
				log(ERROR, "recv() connection closed prematurely")
				goto finally;
			} else {
				totalBytesRcvd += numBytes; // Keep tally of total bytes
				buffer[numBytes] = '\0';    // Terminate the string!
				log(INFO, "%s", buffer);    // Print the echo buffer
			}
		}*/
	}
		
	finally:
	free(echoString);
	close(sock);
	return 0;
}