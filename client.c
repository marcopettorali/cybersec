#include <errno.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "game_util.h"
#include "message.h"
#include "net.h"
#include "util.h"

typedef struct {
    int sock;
    struct sockaddr address;
    int addr_len;
    bool master;
} Connection;

typedef struct {
    Connection *connection;
    AuthenticationInstanceToPlay *authenticationInstanceToPlay;
} InfoToPlay;

void *thread_handler_gaming(void *ptr) {
    InfoToPlay *infoToPlay;
    if (!ptr) pthread_exit(0);
    infoToPlay = (InfoToPlay *)ptr;
    Message *mex;

    printf("[Thread handling game] : started\n");
    printf("[Thread handling game] : Local nickname %s\n", infoToPlay->authenticationInstanceToPlay->nickname_local);
    printf("[Thread handling game] : Opponent nickname %s\n", infoToPlay->authenticationInstanceToPlay->nickname_opponent);
    if (infoToPlay->connection->master == true) {
        memcpy(infoToPlay->authenticationInstanceToPlay->nickname_master,infoToPlay->authenticationInstanceToPlay->nickname_local,NICKNAME_LENGTH);
        memcpy(infoToPlay->authenticationInstanceToPlay->nickname_slave,infoToPlay->authenticationInstanceToPlay->nickname_opponent,NICKNAME_LENGTH);
        Message *received_msg = (Message *)malloc(sizeof(Message));
        #if defined VERBOSE_LEVEL
            printf("I'm the master of the game\n");
        #endif
        mex = create_M1_CLIENT_CLIENT_AUTH(infoToPlay->authenticationInstanceToPlay);
        if (send_MESSAGE(infoToPlay->connection->sock, mex)){
            #if defined PROTOCOL_DEBUG
                printf("M1_CLIENT_CLIENT_AUTH sent\n");
            #endif
        }
        free_MESSAGE(&mex);
        while (1) {
            read_MESSAGE(infoToPlay->connection->sock, received_msg);
            switch (received_msg->opcode) {
                case M2_CLIENT_CLIENT_AUTH:
                    if ((infoToPlay->authenticationInstanceToPlay == NULL) ||
                        (infoToPlay->authenticationInstanceToPlay->expected_opcode != M2_CLIENT_CLIENT_AUTH)) {
                        printf("Unexpected M2_CLIENT_CLIENT_AUTH\nAbort\n");
                        pthread_exit(NULL);
                    }
                    if (handler_M2_CLIENT_CLIENT_AUTH(received_msg->payload, received_msg->payload_len, infoToPlay->authenticationInstanceToPlay,
                                                      infoToPlay->authenticationInstanceToPlay->local_priv_key) != 1) {
                        printf("Unable to handle M2_CLIENT_CLIENT_AUTH correctly\nAbort\n");
                        pthread_exit(NULL);
                    }
                    #if defined PROTOCOL_DEBUG
                        printf("M2_CLIENT_CLIENT_AUTH correctly handled\n");
                    #endif
                    mex = create_M3_CLIENT_CLIENT_AUTH(infoToPlay->authenticationInstanceToPlay);
                    if (send_MESSAGE(infoToPlay->connection->sock, mex)){
                        #if defined PROTOCOL_DEBUG
                            printf("M3_CLIENT_CLIENT_AUTH sent\n");
                        #endif
                    }
                    free_MESSAGE(&mex);
                    break;

                case M4_CLIENT_CLIENT_AUTH:
                    if ((infoToPlay->authenticationInstanceToPlay == NULL) ||
                        (infoToPlay->authenticationInstanceToPlay->expected_opcode != M4_CLIENT_CLIENT_AUTH)) {
                        printf("Unexpected M4_CLIENT_CLIENT_AUTH\nAbort\n");
                        pthread_exit(NULL);
                    }
                    if (handler_M4_CLIENT_CLIENT_AUTH(received_msg->payload, received_msg->payload_len, infoToPlay->authenticationInstanceToPlay) !=1) {
                        printf("Unable to handle M4_CLIENT_CLIENT_AUTH correctly\nAbort\n");
                        pthread_exit(NULL);
                    }

                    mex = create_M5_CLIENT_CLIENT_AUTH(infoToPlay->authenticationInstanceToPlay);
                    if (send_MESSAGE(infoToPlay->connection->sock, mex)){
                        #if defined PROTOCOL_DEBUG
                            printf("M5_CLIENT_CLIENT_AUTH sent\n");
                        #endif
                    }
                    free_MESSAGE(&mex);

                    // authentication done: the game can start!
                    if (game_run(&infoToPlay->authenticationInstanceToPlay->nickname_local[0],
                                 &infoToPlay->authenticationInstanceToPlay->nickname_opponent[0],
                                 &infoToPlay->authenticationInstanceToPlay->symmetric_key[0], infoToPlay->connection->sock, 0) == GAME_END_ERROR) {
                        printf("Lost connection with the opponent\n");
                        pthread_exit(NULL);
                    } else {
                        printf("Game ended correctly!\n");
                        pthread_exit(0);
                        break;
                    }
            }
        }
    } else {
        #if defined VERBOSE_LEVEL
            printf("I'm the slave\n");
        #endif
        memcpy(infoToPlay->authenticationInstanceToPlay->nickname_master,infoToPlay->authenticationInstanceToPlay->nickname_opponent,NICKNAME_LENGTH);
        memcpy(infoToPlay->authenticationInstanceToPlay->nickname_slave,infoToPlay->authenticationInstanceToPlay->nickname_local,NICKNAME_LENGTH);
        Message *received_msg = (Message *)malloc(sizeof(Message));
        infoToPlay->authenticationInstanceToPlay->expected_opcode = M1_CLIENT_CLIENT_AUTH;

        while (1) {
            read_MESSAGE(infoToPlay->connection->sock, received_msg);
            switch (received_msg->opcode) {
                case M1_CLIENT_CLIENT_AUTH:
                    if ((infoToPlay->authenticationInstanceToPlay == NULL) ||
                        (infoToPlay->authenticationInstanceToPlay->expected_opcode != M1_CLIENT_CLIENT_AUTH)) {
                        printf("Unexpected M1_CLIENT_CLIENT_AUTH\nAbort\n");
                        pthread_exit(NULL);
                    }
                    if (handler_M1_CLIENT_CLIENT_AUTH(received_msg->payload, received_msg->payload_len, infoToPlay->authenticationInstanceToPlay) !=1) {
                        printf("Unable to handle M1_CLIENT_CLIENT_AUTH correctly\nAbort\n");
                        pthread_exit(NULL);
                    }
                    #if defined PROTOCOL_DEBUG
                        printf("M1_CLIENT_CLIENT_AUTH correctly handled\n");
                    #endif
                    mex = create_M2_CLIENT_CLIENT_AUTH(infoToPlay->authenticationInstanceToPlay);
                    if (send_MESSAGE(infoToPlay->connection->sock, mex)){
                        #if defined PROTOCOL_DEBUG
                            printf("M2_CLIENT_CLIENT_AUTH sent\n");
                        #endif
                    }
                    free_MESSAGE(&mex);
                    break;
                case M3_CLIENT_CLIENT_AUTH:
                    if ((infoToPlay->authenticationInstanceToPlay == NULL) ||
                        (infoToPlay->authenticationInstanceToPlay->expected_opcode != M3_CLIENT_CLIENT_AUTH)) {
                        printf("Unexpected M3_CLIENT_CLIENT_AUTH\nAbort\n");
                        pthread_exit(NULL);
                    }
                    if (handler_M3_CLIENT_CLIENT_AUTH(received_msg->payload, received_msg->payload_len, infoToPlay->authenticationInstanceToPlay,
                                                      infoToPlay->authenticationInstanceToPlay->local_priv_key) != 1) {
                        printf("Unable to handle M3_CLIENT_CLIENT_AUTH correctly\nAbort\n");
                        pthread_exit(NULL);
                    }
                    mex = create_M4_CLIENT_CLIENT_AUTH(infoToPlay->authenticationInstanceToPlay);
                    if (send_MESSAGE(infoToPlay->connection->sock, mex)) {
                        #if defined PROTOCOL_DEBUG
                            printf("M4_CLIENT_CLIENT_AUTH sent\n");
                        #endif
                        free_MESSAGE(&mex);
                    } else {
                        printf("Unable to create M4_CLIENT_CLIENT_AUTH\nAbort\n");
                        pthread_exit(NULL);
                    }

                    read_MESSAGE(infoToPlay->connection->sock,received_msg);
                    if(received_msg->opcode != M5_CLIENT_CLIENT_AUTH || handler_M5_CLIENT_CLIENT_AUTH(received_msg->payload, received_msg->payload_len, infoToPlay->authenticationInstanceToPlay) != 1){
                        printf("Unable to handle M5_CLIENT_CLIENT_AUTH correctly\nAbort\n");
                        pthread_exit(NULL);
                    }
                    #if defined PROTOCOL_DEBUG
                        printf("M5_CLIENT_CLIENT_AUTH correctly handled\n");
                    #endif

                    // authentication done: the game can start!
                    if (game_run(&infoToPlay->authenticationInstanceToPlay->nickname_local[0],
                                 &infoToPlay->authenticationInstanceToPlay->nickname_opponent[0],
                                 &infoToPlay->authenticationInstanceToPlay->symmetric_key[0], infoToPlay->connection->sock, 1) == GAME_END_ERROR) {
                        printf("Lost connection with the opponent\n");
                        pthread_exit(NULL);
                    } else {
                        printf("Game ended correctly!\n");
                        pthread_exit(0);
                        break;
                    }
            }
        }
    }

    printf("[Thread handling game] : ended in a anomalous way\n");
    pthread_exit(NULL);
}

void handling_connection_to_server(char *buffer, char *command, int port_p2p) {
    int port;
    int sock = -1;
    struct sockaddr_in address;
    struct hostent *host;

    int msg = MSG_OK;

    Connection *connection_to_play;
    pthread_t thread_to_play;

    // Login Username,password
    // read my private key file from keyboard:
    // if the file is protected, a prompt shows up automatically
    char username_client[NICKNAME_LENGTH];
    EVP_PKEY *prvkey = NULL;
    if (client_authentication(username_client, &prvkey) == false) {
        exit(1);
    } else {
        printf(GREEN "**Successful authentication**\n" RESET);
    }
    //**START CONNECTING TO SERVER SOCKET**
    do {
        memset(buffer, 0, COMMAND_SIZE);
        memset(command, 0, COMMAND_SIZE);
        printf("Insert server address -> ");
        secure_input(buffer, COMMAND_SIZE);
        sscanf(buffer, "%s", command);
        host = gethostbyname(command);
        if (!host) {
            printf("Host not valid: retry\n");
            continue;
        }
        memset(buffer, 0, COMMAND_SIZE);
        printf("Insert server port -> ");
        secure_input(buffer, COMMAND_SIZE);
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
    if (connect(sock, (struct sockaddr *)&address, sizeof(address))) {
        fprintf(stderr, "error: cannot connect to server \n");
        return;
    }

    // create the sock for p2p gaming (where we're listening)
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
    #if defined VERBOSE_LEVEL
        printf("Sock to play is ready and listening\n");
        printf("Socket connected to server\n");
    #endif
    //**END CONNECTING TO SERVER SOCKET**

    //**START AUTHENTICATION AND KEY ESTABLISHMENT**

    // handling messages
    Message *mex_received = (Message *)malloc(sizeof(Message));
    // handling authentication
    AuthenticationInstance *authenticationInstance = (AuthenticationInstance *)malloc(sizeof(AuthenticationInstance));
    // handling authentication client_client to play
    AuthenticationInstanceToPlay *authenticationInstanceToPlay;

    #if defined PROTOCOL_DEBUG
        printf(RED "**Establishing secure connection**\n" RESET);
    #endif
    Message *mex = create_M1_CLIENT_SERVER_AUTH(username_client, authenticationInstance);
    if (send_MESSAGE(sock, mex)){
        #if defined PROTOCOL_DEBUG
            printf("M1_CLIENT_SERVER sent\n");
        #endif
    }
    free_MESSAGE(&mex);

    // Waiting for M2_CLIENT_SERVER_AUTH
    read(sock, &mex_received->opcode, OPCODE_SIZE);
    if (mex_received->opcode != M2_CLIENT_SERVER_AUTH) {
        printf("Expected M2_CLIENT_SERVER_AUTH but arrived another mex\nAbort\n");
        close(sock);
        close(sock_to_play);
        return;
    }

    read_MESSAGE_payload(sock, mex_received);

    if (handler_M2_CLIENT_SERVER_AUTH(mex_received->payload, mex_received->payload_len, authenticationInstance, prvkey) != 1) {
        free(authenticationInstance);
        printf("Error in handler_M2_CLIENT_SERVER_AUTH\nAbort");
        close(sock);
        close(sock_to_play);
        return;
    }

    #if defined PROTOCOL_DEBUG
        printf("M2_CLIENT_SERVER_AUTH handled correctly\n");
    #endif

    mex = create_M3_CLIENT_SERVER_AUTH(authenticationInstance, prvkey);
    if (send_MESSAGE(sock, mex)){
        #if defined PROTOCOL_DEBUG
            printf("M3_CLIENT_SERVER_AUTH sent\n");
        #endif
    }
    free_MESSAGE(&mex);

    // Waiting for M4_CLIENT_SERVER_AUTH
    read(sock, &mex_received->opcode, OPCODE_SIZE);
    if (mex_received->opcode != M4_CLIENT_SERVER_AUTH) {
        printf("Expected M4_CLIENT_SERVER_AUTH but arrived another mex\nAbort\n");
        close(sock);
        close(sock_to_play);
        return;
    }

    read_MESSAGE_payload(sock, mex_received);

    if (handler_M4_CLIENT_SERVER_AUTH(mex_received->payload, mex_received->payload_len, authenticationInstance) != 1) {
        free(authenticationInstance);
        printf("Error in handler_M4_CLIENT_SERVER_AUTH\nAbort");
        close(sock);
        close(sock_to_play);
        return;
    }

     #if defined PROTOCOL_DEBUG
        printf("M4_CLIENT_SERVER_AUTH handled correctly\n");
    #endif

    mex = create_M5_CLIENT_SERVER_AUTH(authenticationInstance);
    if (send_MESSAGE(sock, mex)){
        #if defined PROTOCOL_DEBUG
            printf("M5_CLIENT_SERVER_AUTH sent\n");
        #endif
    }
    free_MESSAGE(&mex);

    printf(GREEN "**Secure connection established**\n" RESET);

    //**END AUTHENTICATION AND KEY ESTABLISHMENT

    // Tell him on which port I will listen for p2p port (since we cannot listen on the same port of other local players)
    mex = create_M_LISTEN_PORT_CLIENT_P2P(port_p2p, authenticationInstance);
    if (send_MESSAGE(sock, mex)){
        #if defined PROTOCOL_DEBUG
            printf("M_LISTEN_PORT_CLIENT_P2P sent\n");
        #endif
    }
    free_MESSAGE(&mex);

    authenticationInstance->expected_opcode =
        (char)SUCCESSFUL_CLIENT_AUTHENTICATION_AND_CONFIGURATION;  // from now on expected opcode > SUCCESSFUL_CLIENT_AUTHENTICATION_AND_CONFIGURATION

    while (1) {
        msg = MSG_OK;
        printf(BLUE "> " RESET);
        fflush(stdout);  // To force flushing the stdout without inserting \n
        // We'll use a select to be aware if the server has sent something or the user has inserted something (Refer to Vallati's notes)
        fd_set read_fds;
        int fdmax = sock > STDIN_FILENO ? sock : STDIN_FILENO;
        fdmax = sock_to_play > fdmax ? sock_to_play : fdmax;
        // printf("fdmax -> %d", fdmax);
        FD_ZERO(&read_fds);
        // STDIN_FILENO is the file descriptior related to stdin (that in instead a FILE *)
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(sock, &read_fds);
        FD_SET(sock_to_play, &read_fds);

        //"Select" blocks until a file descriptor is ready
        select(fdmax + 1, &read_fds, NULL, NULL, NULL);
        // check which one is ready
        for (int i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) {
                if (i == STDIN_FILENO) {
                    if (msg != MSG_OK) {
                        // handle_msg(msg);
                        msg = MSG_OK;
                    }
                    // The user has inserted something
                    // printf("The user has inserted something\n");
                    memset(buffer, 0, COMMAND_SIZE);
                    memset(command, 0, COMMAND_SIZE);
                    secure_input(buffer, COMMAND_SIZE);
                    sscanf(buffer, "%s", command);

                    if (strcmp(command, "list") == 0) {
                        mex = create_M_REQ_LIST(authenticationInstance);
                        if (send_MESSAGE(sock, mex)){
                            #if defined PROTOCOL_DEBUG
                                printf("M_REQ_LIST sent\n");
                            #endif
                        }
                        free_MESSAGE(&mex);

                        // Waiting for M_RES_LIST
                        read(sock, &mex_received->opcode, OPCODE_SIZE);
                        if (mex_received->opcode != M_RES_LIST) {
                            printf("Expected M_RES_LIST but arrived another mex\nAbort\n");
                            close(sock);
                            close(sock_to_play);
                            return;
                        }

                        read_MESSAGE_payload(sock, mex_received);

                        char *list_buffer = NULL;
                        if (handler_M_RES_LIST(mex_received->payload, mex_received->payload_len, authenticationInstance, &list_buffer) != 1) {
                            free(authenticationInstance);
                            printf("Error in handler_M_RES_LIST\nAbort");
                            close(sock);
                            close(sock_to_play);
                            return;
                        }
                        #if defined PROTOCOL_DEBUG
                            printf("M_RES_LIST handled correctly\n");
                        #endif
                        // print list
                        if (mex_received->payload_len == 1) {
                            printf("Nobody is available.. please retry after a while\n");
                        } else {
                            printf("List received:\n%s", list_buffer);
                        }

                        free(list_buffer);

                    } else if (strcmp(command, "play") == 0) {
                        msg = MSG_OK;

                        printf("Insert the adversary username -> ");

                        char username_opponent[NICKNAME_LENGTH];
                        //secure_input(username_opponent, NICKNAME_LENGTH);
                        fgets(username_opponent, NICKNAME_LENGTH, stdin);
                        username_opponent[NICKNAME_LENGTH - 1] = '\0';

                        mex = create_M_REQ_PLAY(username_opponent, authenticationInstance);
                        if (send_MESSAGE(sock, mex)){
                            #if defined PROTOCOL_DEBUG
                                printf("M_REQ_PLAY sent\n");
                            #endif
                        }
                        free_MESSAGE(&mex);

                        // Waiting for M_RES_PLAY_OPPONENT
                        read(sock, &mex_received->opcode, OPCODE_SIZE);
                        if (mex_received->opcode != M_RES_PLAY_OPPONENT) {
                            printf("Expected M_RES_PLAY_OPPONENT but arrived another mex\nAbort\n");
                            close(sock);
                            close(sock_to_play);
                            return;
                        }

                        read_MESSAGE_payload(sock, mex_received);

                        char answer;
                        int opponent_port;

                        if (handler_M_RES_PLAY_OPPONENT(mex_received->payload, mex_received->payload_len, authenticationInstance, &answer,
                                                        &opponent_port) != 1) {
                            free(authenticationInstance);
                            printf("Error in M_RES_PLAY_OPPONENT\nAbort");
                            close(sock);
                            close(sock_to_play);
                            return;
                        }
                        #if defined PROTOCOL_DEBUG
                            printf("M_RES_PLAY_OPPONENT handled correctly\n");
                        #endif

                        if ((answer != '1')) {
                            printf("The opponent has rejected\n");
                        } else {
                            printf("He has accepted\n");

                            // get the parts of the opponent address_in struct (!!---we should read also the ip---!!))
                            #if defined VERBOSE_LEVEL
                                printf("We'll contact the opponent on %d port\n", opponent_port);
                            #endif

                            // WAIT FOR OPPONENT INFO
                            // here will received the MASTER

                            read(sock, &mex_received->opcode, OPCODE_SIZE);
                            if (mex_received->opcode != M_PRELIMINARY_INFO_OPPONENT) {
                                printf("Expected M_PRELIMINARY_INFO_OPPONENT but arrived another mex\nAbort\n");
                                close(sock);
                                close(sock_to_play);
                                return;
                            }

                            #if defined PROTOCOL_DEBUG
                                printf("Received M_PRELIMINARY_INFO_OPPONENT (master)\n");
                            #endif

                            authenticationInstanceToPlay = (AuthenticationInstanceToPlay *)malloc(sizeof(AuthenticationInstanceToPlay));

                            read_MESSAGE_payload(sock, mex_received);

                            if (handler_M_PRELIMINARY_INFO_OPPONENT(mex_received->payload, mex_received->payload_len, authenticationInstance,
                                                                    authenticationInstanceToPlay) != 1) {
                                free(authenticationInstance);
                                printf("Error in M_PRELIMINARY_INFO_OPPONENT\nAbort");
                                close(sock);
                                close(sock_to_play);
                                return;
                            }
                            #if defined PROTOCOL_DEBUG
                                printf("M_PRELIMINARY_INFO_OPPONENT handled correctly\n");
                            #endif
                            authenticationInstanceToPlay->local_priv_key = prvkey;

                            // SHOULD BE PASSED to thread gaming

                            // -------------------------
                            // START A NEW THREAD TO handle the game with THE OPPONENT.. WE'LL DO A JOIN ON IT SO WE'll resume the communication with
                            // the server only when the game is finished send e poi dire che è master e passare al thread infoToPlay
                            int sock_to_play_master = socket(AF_INET, SOCK_STREAM, 0);
                            if (sock_to_play_master <= 0) {
                                fprintf(stderr, "error: cannot create socket for contacting the opponent\n");
                                return;
                            }

                            // connect to the opponent
                            struct sockaddr_in address_of_opponent;
                            struct hostent *host_opponent;

                            host_opponent = gethostbyname("127.0.0.1");  // should be the ip read by the socket (sent by the server)
                            address_of_opponent.sin_family = AF_INET;
                            address_of_opponent.sin_port = htons(opponent_port);

                            memcpy(&address_of_opponent.sin_addr, host_opponent->h_addr_list[0], host_opponent->h_length);
                            if (connect(sock_to_play_master, (struct sockaddr *)&address_of_opponent, sizeof(address_of_opponent))) {
                                fprintf(stderr, "error: cannot connect to the opponent \n");
                                return;
                            }

                            connection_to_play = (Connection *)malloc(sizeof(Connection));
                            connection_to_play->sock = sock_to_play_master;
                            connection_to_play->master = true;

                            // Inform the server that we're goign to play so its thread will wait for the end
                            mex = create_M1_INFORM_SERVER_GAME_START(authenticationInstance);
                            if (send_MESSAGE(sock, mex)){
                                #if defined PROTOCOL_DEBUG
                                    printf("M1_INFORM_SERVER_GAME_START sent\n");
                                #endif
                            }
                            free_MESSAGE(&mex);

                            InfoToPlay *infoToPlay = (InfoToPlay *)malloc(sizeof(InfoToPlay));
                            infoToPlay->connection = connection_to_play;
                            infoToPlay->authenticationInstanceToPlay = authenticationInstanceToPlay;

                            pthread_create(&thread_to_play, 0, thread_handler_gaming, (void *)infoToPlay);
                            pthread_join(thread_to_play, NULL);

                            #if defined VERBOSE_LEVEL
                                printf("Game ended: inform the server about it\n");
                            #endif
                            // to inform the server's thread that we've finished
                            mex = create_M1_INFORM_SERVER_GAME_END(authenticationInstance);
                            if (send_MESSAGE(sock, mex)){
                                #if defined PROTOCOL_DEBUG
                                    printf("M1_INFORM_SERVER_GAME_END sent\n");
                                #endif
                            }
                            free_MESSAGE(&mex);

                            free(connection_to_play);
                            close(sock_to_play_master);  // since each time he's the master, he will instantiate another sock
                        }

                    } else if (strcmp(command, "help") == 0) {
                        msg = MSG_SHOW_GUIDE_CLIENT_SERVER_INTERACTION;
                        handle_msg(msg);
                    } else if (strcmp(command, "close") == 0) {
                        mex = create_M_CLOSE(authenticationInstance);
                        if (send_MESSAGE(sock, mex)){
                            #if defined PROTOCOL_DEBUG
                                printf("M_CLOSE sent\n");
                            #endif
                        }
                        free_MESSAGE(&mex);

                        close(sock);
                        // close also our socket for gaming
                        close(sock_to_play);
                        // We should come back to main menu so return;
                        return;

                    } else {
                        msg = MSG_COMMAND_NOT_FOUND;
                    }

                } else if (i == sock) {
                    // The server has sent something
                    // One cause: it wants to tell me that someone has requested to challenge me (INT CODE=3)
                    #if defined VERBOSE_LEVEL
                        printf("The server has sent something\n");
                    #endif
                    // let's read it

                    read_MESSAGE(sock, mex_received);

                    if (mex_received->opcode == M_REQ_ACCEPT_PLAY_TO_ACK) {
                        if (handler_M_REQ_ACCEPT_PLAY_TO_ACK(mex_received->payload, mex_received->payload_len, authenticationInstance) != 1) {
                            free(authenticationInstance);
                            printf("Error in handler_M_REQ_ACCEPT_PLAY_TO_ACK\nAbort");
                            close(sock);
                            close(sock_to_play);
                            return;
                        }

                        free_MESSAGE(&mex_received);
                        mex_received = (Message *)malloc(sizeof(Message));

                        #if defined PROTOCOL_DEBUG
                            printf("M_REQ_ACCEPT_PLAY_TO_ACK handled correctly\n");
                        #endif

                        printf("%s has requested to challenge you\nDo you want to accept?\n", authenticationInstance->nickname_opponent_required);
                        char answer;
                        scanf(" %c", &answer);

                        mex = create_M_RES_ACCEPT_PLAY_ACK(answer, authenticationInstance);
                        if (send_MESSAGE(sock, mex)){
                            #if defined PROTOCOL_DEBUG
                                printf("M_RES_ACCEPT_PLAY_ACK sent\n");
                            #endif
                        }
                        free_MESSAGE(&mex);

                        if (answer == '1') {
                            // WAIT FOR M_PRELIMINARY_INFO_OPPONENT
                            free_MESSAGE(&mex_received);
                            mex_received = (Message *)malloc(sizeof(Message));

                            read(sock, &mex_received->opcode, OPCODE_SIZE);
                            if (mex_received->opcode == M_PRELIMINARY_INFO_OPPONENT) {
                                // here will received the slave
                                #if defined PROTOCOL_DEBUG
                                printf("The server has sent the opponent's info (slave)\n");
                                #endif
                                read_MESSAGE_payload(sock, mex_received);
                                  
                                authenticationInstanceToPlay = (AuthenticationInstanceToPlay *)malloc(sizeof(AuthenticationInstanceToPlay));

                                if (handler_M_PRELIMINARY_INFO_OPPONENT(mex_received->payload, mex_received->payload_len, authenticationInstance,
                                                                        authenticationInstanceToPlay) != 1) {
                                    free(authenticationInstance);
                                    printf("Error in M_PRELIMINARY_INFO_OPPONENT\nAbort");
                                    close(sock);
                                    close(sock_to_play);
                                    return;
                                }
                                #if defined PROTOCOL_DEBUG
                                    printf("M_PRELIMINARY_INFO_OPPONENT handled correctly\n");
                                #endif
                                authenticationInstanceToPlay->local_priv_key = prvkey;
                            } else {
                                printf("Expected M_PRELIMINARY_INFO_OPPONENT but arrived another mex\nABORT\n");
                                free(authenticationInstance);
                                printf("Error in M_PRELIMINARY_INFO_OPPONENT\nAbort");
                                close(sock);
                                close(sock_to_play);
                                return;
                            }
                        }
                    }
                    if (mex_received->opcode == M_CLOSE) {
                        if (handler_M_CLOSE(mex_received->payload, mex_received->payload_len, authenticationInstance) != 1) {
                            printf("M_CLOSE is not valid: continue to work\n");
                        } else {
                            printf("M_CLOSE handled correctly: closing from server side\n");
                            free(authenticationInstance);
                            close(sock);
                            close(sock_to_play);
                            return;
                        }
                    }

                    // then when the opponent will contact us he will contact our socket and "select" will alert us

                } else if (i == sock_to_play) {
                    // do ACCEPT A NEW INCOMING REQUEST
                    // printf("In sock_to_play\n");
                    /* accept incoming connections */
                    connection_to_play = (Connection *)malloc(sizeof(Connection));
                    // printf("After instantiation\n");
                    connection_to_play->sock = accept(sock_to_play, &connection_to_play->address, &connection_to_play->addr_len);
                    // printf("After accept\n");
                    // printf("connection_to_play->sock %d\n",connection_to_play->sock);
                    // check if accept has return a valid socketID
                    if (connection_to_play->sock > 0) {
                        #if defined VERBOSE_LEVEL
                            printf("Someone has contact us to play\n");
                        #endif
                        // Inform the server that we're goign to play so its thread will wait for the end
                        mex = create_M1_INFORM_SERVER_GAME_START(authenticationInstance);
                        if (send_MESSAGE(sock, mex)){
                            #if defined PROTOCOL_DEBUG
                                printf("M1_INFORM_SERVER_GAME_START sent\n");
                            #endif
                        }
                        free_MESSAGE(&mex);


                        connection_to_play->master = false;  // to state that this thread has been contected

                        InfoToPlay *infoToPlay = (InfoToPlay *)malloc(sizeof(InfoToPlay));
                        infoToPlay->connection = connection_to_play;
                        infoToPlay->authenticationInstanceToPlay = authenticationInstanceToPlay;

                        pthread_create(&thread_to_play, 0, thread_handler_gaming, (void *)infoToPlay);
                        pthread_join(thread_to_play, NULL);

                        #if defined VERBOSE_LEVEL
                            printf("Game ended: inform the server about it\n");
                        #endif

                        mex = create_M1_INFORM_SERVER_GAME_END(authenticationInstance);
                        if (send_MESSAGE(sock, mex)){
                            #if defined PROTOCOL_DEBUG
                                printf("M1_INFORM_SERVER_GAME_END sent\n");
                            #endif
                        }
                        free_MESSAGE(&mex);

                      

                    } else {
                        printf("Oh dear, something went wrong with accept()! %s\n", strerror(errno));
                    }

                    close(connection_to_play->sock);
                    free(connection_to_play);
                    /*--------------------*/
                }
            }
        }
    }

    return;
}

int main(int argc, char **argv) {
    int msg = MSG_OK;
    char *buffer = (char *)malloc(COMMAND_SIZE);
    char *command = (char *)malloc(COMMAND_SIZE);
    int port_p2p;

    printf("COMMAND = %s\n", buffer);

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
        printf(BLUE "> " RESET);

        // clear buffers for storing commands
        memset(buffer, 0, COMMAND_SIZE);
        memset(command, 0, COMMAND_SIZE);

        // read commands from user's input
        secure_input(buffer, COMMAND_SIZE);
        sscanf(buffer, "%s", command);

        // decode the inserted command and handle msgs
        if (strcmp(command, "server") == 0) {
            handling_connection_to_server(buffer, command, port_p2p);
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