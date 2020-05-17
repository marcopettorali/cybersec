#include <netdb.h>
#include <stdio.h>
#include<stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <stdbool.h>
#include <pthread.h>

#include "util.h"

typedef struct {
    int sock;
    struct sockaddr address;
    int addr_len;
	bool master;
} Connection;

void *thread_handler_gaming(void *ptr) {
	Connection *conn;
	if (!ptr) pthread_exit(0);
    conn = (Connection *)ptr;

	printf("[Thread handling game] : started\n");
	printf("[Thread handling game] : ");
	if(conn->master==true)
		printf("I'm the master of the game\n");
	else
		printf("I'm the slave\n");
	sleep(5);

	/*
		HERE SHOULD BE PUT THE GAME LOGIC
	*/

	printf("[Thread handling game] : ended\n");

	pthread_exit(0);
}


void handling_connection_to_server(char* buffer, char* command,int port_p2p){
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

	Connection *connection_to_play;
    pthread_t thread_to_play;

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

	//create the sock for p2p gaming (where we're listening)
	/* create socket */
	struct sockaddr_in my_addr;
	int sock_to_play;
    sock_to_play = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_to_play <= 0) {
        fprintf(stderr, "error: cannot create socket\n");
        return;
    }

    /* bind socket to port */
    my_addr.sin_family = AF_INET;
    my_addr.sin_addr.s_addr = INADDR_ANY;
    my_addr.sin_port = htons(port_p2p);
    if (bind(sock_to_play, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in)) < 0) {
        fprintf(stderr, "error: cannot bind p2p socket to port %d\n", port_p2p);
        return;
    }

    /* listen on port */
    if (listen(sock_to_play, BACKLOG_LISTEN_QUEUE) < 0) {
        fprintf(stderr, "error: cannot listen on port\n");
        return;
    }
    // listen return 0 if ok
    printf("Sock to play is ready and listening\n");
	
	/*-------*/


	/* chatting with the server */
	printf("Connection to the server established\n");
	//Tell him on which port I will listen for p2p port (since we cannot listen on the same port of other local players)
	int command_to_tell_port = 8;
	send(sock, &command_to_tell_port, sizeof(int), 0);
	send(sock, &port_p2p, sizeof(int), 0);
	while (1) {
		msg = MSG_OK;
		printf("> ");
		fflush(stdout); //To force flushing the stdout without inserting \n
		//We'll use a select to be aware if the server has sent something or the user has inserted something (Refer to Vallati's notes)
		fd_set read_fds;
		int fdmax = sock > STDIN_FILENO ? sock : STDIN_FILENO;
		fdmax = sock_to_play > fdmax ? sock_to_play : fdmax;
		//printf("fdmax -> %d", fdmax);
    	FD_ZERO(&read_fds);
		//STDIN_FILENO is the file descriptior related to stdin (that in instead a FILE *)
		FD_SET(STDIN_FILENO, &read_fds);
		FD_SET(sock, &read_fds);
		FD_SET(sock_to_play, &read_fds);
							
		//"Select" blocks until a file descriptor is ready
		select(fdmax + 1, &read_fds , NULL, NULL, NULL);
		//check which one is ready
		for(int i=0; i<= fdmax; i++){
			if(FD_ISSET(i,&read_fds)){
				if(i == STDIN_FILENO){
					if (msg != MSG_OK) {
						handle_msg(msg);
						msg = MSG_OK;
					}
					//The user has inserted something
					//printf("The user has inserted something\n");
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
						msg = MSG_OK;
						//len=1 == TELL SERVER THAT WE WANT THE LIST
						len = 1;
						write(sock, &len, sizeof(int));
						//has to wait for receiving answer
						/* read lenght buffer */
						int list_lenght;
						read(sock, &list_lenght, sizeof(int));
						printf("Received lenght -> %d\n",list_lenght);
						char * list_buffer = malloc( sizeof(char) * list_lenght );
						/* read message */
						read(sock, list_buffer, list_lenght);
						//printf("Size of buffer_received %ld",strlen(buffer_received));
						printf("**FORMAT LIST**\n(<nickname_online_user>,0(free)/1(in game),<nickname_adversary..if exists>)\nList received:\n%s\n",list_buffer);
						free(list_buffer);
					} else if (strcmp(command, "play") == 0) {
						msg = MSG_OK;
						memset(buffer, 0, COMMAND_SIZE);
						memset(command, 0, COMMAND_SIZE);
						printf("Insert the adversary username -> ");
						fgets(buffer, COMMAND_SIZE, stdin);
						sscanf(buffer, "%s", command);
						//len=2 == TELL SERVER THAT WE WANT TO PLAY WITH username
						len = 2;
						write(sock, &len, sizeof(int));
						write(sock,command,strlen(command)+1); //add the last '\0'
						//read the answer
						bool answer;
						printf("..WAITING FOR OPPONENT'S RESPONSE..\n");
						read(sock,&answer,sizeof(bool));
						printf("Response from the opponent -> %d\n",answer);
						if(answer==false){
							printf("The opponent has rejected\n");
						} else
						{
							//get the parts of the opponent address_in struct (!!---we should read also the ip---!!))
							read(sock,&opponent_port,sizeof(uint16_t));
							printf("We'll contact the opponent on %d port\n",opponent_port);

							// -------------------------
							//START A NEW THREAD TO handle the game with THE OPPONENT.. WE'LL DO A JOIN ON IT SO WE'll resume the communication with the server only when the game is finished
							//send e poi dire che è master e passare al thread la connection
							int sock_to_play_master = socket(AF_INET, SOCK_STREAM, 0);
							if (sock_to_play_master <= 0) {
								fprintf(stderr, "error: cannot create socket for contacting the opponent\n");
								return;
							}

							/* connect to the opponent */
							struct sockaddr_in address_of_opponent;
    						struct hostent* host_opponent;

							host_opponent = gethostbyname("127.0.0.1"); //should be the ip read by the socket (sent by the server)
							address_of_opponent.sin_family = AF_INET;
							address_of_opponent.sin_port = htons(opponent_port);

							memcpy(&address_of_opponent.sin_addr, host_opponent->h_addr_list[0], host_opponent->h_length);
							if (connect(sock_to_play_master, (struct sockaddr*)&address_of_opponent, sizeof(address_of_opponent))) {
								fprintf(stderr, "error: cannot connect to the opponent \n");
								return;
							}

							connection_to_play = (Connection *)malloc(sizeof(Connection));
							connection_to_play->sock = sock_to_play_master;
							connection_to_play->master = true;

							pthread_create(&thread_to_play, 0, thread_handler_gaming, (void *)connection_to_play);
							pthread_join(thread_to_play,NULL);

							printf("Game ended: inform the server about it\n");
							// ---------------------------------
							

							//send commandInt= 7 to inform the thread that we've finished
							int commandInt = 7;
							write(sock, &commandInt, sizeof(int));

							free(connection_to_play);
							close(sock_to_play_master); //since each time he's the master, he will instantiate another sock
						}
						

					} else if (strcmp(command, "help") == 0) {
						msg = MSG_SHOW_GUIDE_CLIENT_SERVER_INTERACTION;
						handle_msg(msg);
					} else if (strcmp(command, "close") == 0) {
						/* close socket */
						//to tell the server that we're going to quit
						len = -1;
						write(sock, &len, sizeof(int));
						close(sock);
						//close also our socket for gaming
						close(sock_to_play);
						//We should come back to main menu so return;
						return;
						//break;
					} else {
						msg = MSG_COMMAND_NOT_FOUND;
					}
				
				}else if(i == sock){
					//The server has sent something
					//One cause: it wants to tell me that someone has requested to challenge me (INT CODE=3)
					printf("The server has sent something\n");
					//let's read it
					int mex_code_received;
					read(sock, &mex_code_received, sizeof(int));
					if(mex_code_received == 3){
						//answer the server
						/* read message */
						memset(buffer_received, 0, COMMAND_SIZE);
        				read(sock, buffer_received, COMMAND_SIZE);
						printf("%s has requested to challenge you\nDo you want to accept?\n",buffer_received);
						int answer;
						scanf("%d",&answer);
						//SEND ANSWER TO SERVER
						//es 1 se accettata, 0 se rifiutata
						send(sock, &answer, sizeof(int), 0);
						//then when the opponent will contact us he will contact our socket and "select" will alert us
					}
				}else if(i == sock_to_play){
					//do ACCEPT A NEW INCOMING REQUEST
					
					/* accept incoming connections */
					connection_to_play = (Connection *)malloc(sizeof(Connection));
					connection_to_play->sock = accept(sock_to_play, &connection_to_play->address, &connection_to_play->addr_len);
					// check if accept has return a valid socketID
					if (connection_to_play->sock <= 0) {
						free(connection_to_play);
					} else {
						/* start a new thread and wait for it */
						//send commandInt=6 (inform the server that we're goign to play) so its thread will wait for the end
						int commandInt = 6;
						write(sock, &commandInt, sizeof(int));
						connection_to_play->master=false; //to state that this thread has been contected
						pthread_create(&thread_to_play, 0, thread_handler_gaming, (void *)connection_to_play);
						pthread_join(thread_to_play,NULL);

						printf("Game ended: inform the server about it\n");
						//send commandInt= 7 to inform the thread that we've finished
						commandInt = 7;
						write(sock, &commandInt, sizeof(int));
						
					}
					free(connection_to_play);
					/*--------------------*/
				}
			}
		}

		
	}

	return;
}


int main(int argc, char** argv) {
    
    int msg = MSG_OK;
    char* buffer = (char*)malloc(COMMAND_SIZE);
    char* command = (char*)malloc(COMMAND_SIZE);
	int port_p2p;

	/* check for command line arguments */
    if (argc != 2) {
        fprintf(stderr, "usage: %s port\n", argv[0]);
        return -1;
    }

    /* obtain port number to listen for p2p gaming */
    if (sscanf(argv[1], "%d", &port_p2p) <= 0) {
        fprintf(stderr, "%s: error: wrong parameter: port\n", argv[0]);
        return -2;
    }


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
            handling_connection_to_server(buffer,command,port_p2p);
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