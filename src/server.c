#include <stdio.h>
#include <stdlib.h>
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


int main(int argc, char *argv[]) {
	int master_socket , addrlen , new_socket , client_socket[30] = {0} , max_clients = 30 , activity, i , valread , sd;
	int max_sd;
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
	
	addrlen = sizeof(struct sockaddr_in);
	while (TRUE) { // Run forever
		// Wait for a client to connect
		FD_ZERO(&readfds);

		//add master socket to set
        FD_SET(master_socket, &readfds);
        max_sd = master_socket;	


		//add child sockets to set
        for ( i = 0 ; i < max_clients ; i++) {
            //socket descriptor
            sd = client_socket[i];
             
            //if valid socket descriptor then add to read list
            if(sd > 0) {
                FD_SET( sd , &readfds);
			}
            //highest file descriptor number, need it for the select function
            if(sd > max_sd) {
                max_sd = sd;
			}
        }

		//wait for an activity on one of the sockets , timeout is NULL , so wait indefinitely
        activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);
		if ((activity < 0) && (errno!=EINTR)) {
            printf("select error");
        }

		//If something happened on the master socket , then its an incoming connection
        if (FD_ISSET(master_socket, &readfds)) {
            if ((new_socket = acceptTCPConnection(master_socket)) < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }
          
            
            //send new connection greeting message
            
			/*			POR AHORA NO, TENEMOS QUE VER COMO LO CONTEMPLAMOS EN EL CLIENTE
			if( send(new_socket, message, strlen(message), 0) != strlen(message) ) {
                perror("send");
            }
              
            log(INFO,"Welcome message sent successfully");
            */  


            //add new socket to array of sockets
            for (i = 0; i < max_clients; i++) {
                //if position is empty
                if( client_socket[i] == 0 ) {
                    client_socket[i] = new_socket;
                    log(INFO,"Adding to list of sockets as %d\n" , i);
                     
                    break;
                }
            }
        }

		//else its some IO operation on some other socket :)
        for (i = 0; i < max_clients; i++) 
        {
            sd = client_socket[i];
              
            if (FD_ISSET( sd , &readfds)) 
            {
                if(handleTCPEchoClient(sd) == 0){
					log(INFO,"client number %d was closed\n" , i);
					close(sd);
					client_socket[i] = 0;
				}
            }
        }
	}
}