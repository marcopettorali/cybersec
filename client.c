#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "util.h"

void handling_connection_to_server(char* buffer, char* command){
	int port;
    int sock = -1;
    struct sockaddr_in address;
    struct hostent* host;	

	int len;
	int msg = MSG_OK;

	char* buffer_received = (char*)malloc(COMMAND_SIZE);
    char* command_received = (char*)malloc(COMMAND_SIZE);

	//just to try
	int response;
	uint16_t opponent_port;
	struct sockaddr_in opponent;

	do {
		memset(buffer, 0, COMMAND_SIZE);
		memset(command, 0, COMMAND_SIZE);
		printf("Insert server address -> ");
		fgets(buffer, COMMAND_SIZE, stdin);
		sscanf(buffer, "%s", command);
		host = gethostbyname(command);
		if (!host) {
			printf("Host not valid: retry\n");
			continue;
		}
		memset(buffer, 0, COMMAND_SIZE);
		printf("Insert server port -> ");
		fgets(buffer, COMMAND_SIZE, stdin);
		if (sscanf(buffer, "%d", &port) <= 0 || port <= 0) {
			printf("Port not valid: retry\n");
			continue;
		}
		break;
	} while (1);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock <= 0) {
		fprintf(stderr, "error: cannot create socket\n");
		return;
	}

	/* connect to server */
	address.sin_family = AF_INET;
	address.sin_port = htons(port);

	memcpy(&address.sin_addr, host->h_addr_list[0], host->h_length);
	if (connect(sock, (struct sockaddr*)&address, sizeof(address))) {
		fprintf(stderr, "error: cannot connect to server \n");
		return;
	}

	/* chatting with the server */
	printf("Connection to the server established\n");
	while (1) {
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
			if (send(sock, &len, sizeof(int), 0) < 0) {
				printf("Send failed\n");
				break;
			}
			if (send(sock, command, len, 0) < 0) {
				printf("Send failed\n");
				break;
			}
			
		} else if (strcmp(command, "list") == 0) {

			//len=1 == TELL SERVER THAT WE WANT THE LIST
			len = 1;
			write(sock, &len, sizeof(int));
			//has to wait for receiving answer
			/* read message */
			memset(buffer_received, 0, COMMAND_SIZE);
        	read(sock, buffer_received, COMMAND_SIZE);
			//printf("Size of buffer_received %ld",strlen(buffer_received));
			printf("List received:\n %s",buffer_received);
		} else if (strcmp(command, "play") == 0) {
			memset(buffer, 0, COMMAND_SIZE);
			memset(command, 0, COMMAND_SIZE);
			printf("Insert the adversary username -> ");
			fgets(buffer, COMMAND_SIZE, stdin);
			sscanf(buffer, "%s", command);
			//len=2 == TELL SERVER THAT WE WANT TO PLAY WITH username
			len = 2;
			write(sock, &len, sizeof(int));
			write(sock,command,strlen(command)+1); //add the last '\0'
			//read the response
			read(sock,&response,sizeof(int));
			if(response==0){
				printf("The opponent has rejected\n");
			} else
			{
				//get the parts of the opponent address_in struct
				read(sock,&opponent_port,sizeof(uint16_t));
				printf("We'll contact the opponent on %d port\n",opponent_port);
				//START A NEW THREAD TO CONTACT THE OPPONENT.. WE'LL DO A JOIN ON IT SO WE'll resume the communication with the server only when the game is finished
				//EACH USER HAS A SOCKET BIND TO THE PORT SPECIFIED IN THE HIS NODE
			}
			

		} else if (strcmp(command, "help") == 0) {
			msg = MSG_SHOW_GUIDE_CLIENT_SERVER_INTERACTION;
		} else if (strcmp(command, "close") == 0) {
			/* close socket */
			//to tell the server that we're going to quit
			len = -1;
			write(sock, &len, sizeof(int));
			close(sock);
			break;
		} else {
			msg = MSG_COMMAND_NOT_FOUND;
		}
	}

	return;
}


int main(int argc, char** argv) {
    
    int msg = MSG_OK;
    char* buffer = (char*)malloc(COMMAND_SIZE);
    char* command = (char*)malloc(COMMAND_SIZE);

    while (1) {
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
            handling_connection_to_server(buffer,command);
        } else if (strcmp(command, "help") == 0) {
            msg = MSG_SHOW_GUIDE_CLIENT_DASHBOARD;
        } else if (strcmp(command, "quit") == 0) {
            printf("bye\n");
            break;
        } else {
            msg = MSG_COMMAND_NOT_FOUND;
        }
    }

	free(buffer);
	free(command);

    return 0;
}