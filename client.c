#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>

#include "util.h"

int main(int argc, char ** argv)
{
	int port;
	int sock = -1;
	struct sockaddr_in address;
	struct hostent * host;
	int len;
	
	int msg = MSG_OK;
	char* buffer = (char*)malloc(COMMAND_SIZE);
    char* command = (char*)malloc(COMMAND_SIZE);

	while(1){
		if (msg != MSG_OK) {
            handle_msg(msg);
            msg = MSG_OK;
        }
        printf("> ");

		// clear buffers for storing commands
        memset(buffer, 0, COMMAND_SIZE);
        memset(command, 0, COMMAND_SIZE);

		// read commands from user's input
        fgets(buffer, COMMAND_SIZE, stdin);
        sscanf(buffer, "%s", command);

		// decode the inserted command and handle msgs
        if (strcmp(command, "server") == 0) {
			do{
        		memset(buffer, 0, COMMAND_SIZE);
				memset(command, 0, COMMAND_SIZE);
				printf("Insert server address -> ");
				fgets(buffer, COMMAND_SIZE, stdin);
				sscanf(buffer, "%s", command);
				host = gethostbyname(command);
				if(!host){
					printf("Host not valid: retry\n");
					continue;
				}
				memset(buffer, 0, COMMAND_SIZE);
				printf("Insert server port -> ");
				fgets(buffer, COMMAND_SIZE, stdin);
				if(sscanf(buffer, "%d", &port)<=0 || port<=0){
					printf("Port not valid: retry\n");
					continue;
				}
				break;
			}while(1);

			sock = socket(AF_INET, SOCK_STREAM, 0);
			if (sock <= 0){
				fprintf(stderr, "error: cannot create socket\n");
				return -3;
			}

			/* connect to server */
			address.sin_family = AF_INET;
			address.sin_port = htons(port);

			memcpy(&address.sin_addr, host->h_addr_list[0], host->h_length);
			if (connect(sock, (struct sockaddr *)&address, sizeof(address)))
			{
				fprintf(stderr, "error: cannot connect to host \n");
				continue;
				//return -5;
			}

			/* chatting with the server */
			printf("Connection to the server established\n");
			while (1)
			{
				if (msg != MSG_OK) {
            		handle_msg(msg);
            		msg = MSG_OK;
        		}
        		printf("> ");

				memset(buffer, 0, COMMAND_SIZE);
				memset(command, 0, COMMAND_SIZE);
				fgets(buffer, COMMAND_SIZE, stdin);
				sscanf(buffer, "%s", command);

				if (strcmp(command, "chat") == 0) {
					memset(buffer, 0, COMMAND_SIZE);
					memset(command, 0, COMMAND_SIZE);
					printf("What would you like to tell the server? -> ");
					fgets(buffer, COMMAND_SIZE, stdin);
					sscanf(buffer, "%s", command);


					len = strlen(command);
					if( send(sock , &len , sizeof(int) , 0) < 0){
						printf("Send failed\n");
						break;
					}
					if( send(sock , command , len , 0) < 0){
						printf("Send failed\n");
						break;
					}

				}else if (strcmp(command, "help") == 0) {
            		msg = MSG_SHOW_GUIDE_CLIENT_SERVER_INTERACTION;
        		} else if (strcmp(command, "close") == 0) {
					/* close socket */
					close(sock);
            		break;
        		} else {
            		msg = MSG_COMMAND_NOT_FOUND;
        		}
				
			}
			

		} else if (strcmp(command, "help") == 0) {
			msg = MSG_SHOW_GUIDE_CLIENT_DASHBOARD;
		} else if (strcmp(command, "quit") == 0) {
			printf("bye\n");
			break;
		} else {
			msg = MSG_COMMAND_NOT_FOUND;
		}
	}

	return 0;
}