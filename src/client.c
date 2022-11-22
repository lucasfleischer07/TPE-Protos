#include "./include/client.h"


#define BASE_RESPONSE_DATA      3
#define BUFSIZE 512
#define STDIN 0
#define TRUE 1

int main(const int argc, char *argv[]) {
	struct client_request_args  args[MAX_CLIENT_REQUESTS] = {0};
    struct sockaddr_in          sin4;
    struct sockaddr_in6         sin6;
    enum ip_version             ip_version;
    char                        token[TOKEN_SIZE];

	char writeBuffer[BASE_REQUEST_DATA + MAX_BYTES_DATA];
    uint8_t buf[BASE_RESPONSE_DATA + MAX_BYTES_DATA];

	size_t arg_amount = parse_args(argc,argv,args,token,&sin4,&sin6,&ip_version);

	static uint8_t combinedlen[2] = {0};
    static uint8_t numeric_data_array[4] = {0};
    static uint32_t numeric_response;

	int sock_fd;

	/** como se pueden hacer varias consultas en una sola ejecucion, se realizan de forma bloqueante y una detras de la otra,
	 *  y con distintas conecciones, por lo que despues del recv siepre hay que cerrar el socket y re abrirlo en la prox consulta
	*/
	for(size_t i=0 ; i < arg_amount ; i++){
        if(ip_version == ipv4){
            if((sock_fd = socket(sin4.sin_family, SOCK_STREAM, IPPROTO_TCP)) < 0){
                perror("client socket ipv4 creation");
                return 1;
            }
        
            if(connect(sock_fd, (struct sockaddr *)&sin4, sizeof(sin4)) < 0){
                perror("client socket ipv4 connect");
                return 1;
            }
        } else {
            if((sock_fd = socket(sin6.sin6_family, SOCK_STREAM, IPPROTO_TCP)) < 0){
                perror("client socket ipv6 creation");
                return 1;
            }
        
            if(connect(sock_fd, (struct sockaddr *)&sin6, sizeof(sin6)) < 0){
                perror("client socket ipv6 connect");
                return 1;
            }
        }
    
        serialize_request(&args[i], token, writeBuffer);
                                // version 1 + token 2 + method 1 + dlen 2 + data length
        if(send(sock_fd, &writeBuffer, BASE_REQUEST_DATA + args[i].dlen, 0) < 0){
            perror("client socket send");
            return 1;
        }
        
        long n = -1; 
        while ((n = recv(sock_fd, buf, BASE_RESPONSE_DATA + MAX_BYTES_DATA, 0)) != 0) {
            if (n < 0) {
                perror("client socket recv");
                abort();
            }
        }

        // termine de recibir
        process_response(buf[0], &args[i], buf,combinedlen, numeric_data_array, &numeric_response);


        if(close(sock_fd) < 0){
            perror("client socket close");
            return 1;
        }

        memset(writeBuffer, 0, BASE_REQUEST_DATA + MAX_BYTES_DATA);
        memset(buf, 0, BASE_RESPONSE_DATA + MAX_BYTES_DATA);
        memset(combinedlen, 0, 2);
        memset(numeric_data_array, 0, 4);
    }

	return 0;
}
