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

	
	return 0;
}