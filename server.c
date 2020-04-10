#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "util.h"

typedef struct {
    int sock;
    struct sockaddr address;
    int addr_len;
} Connection;

void *thread_handler_client(void *ptr) {
    char *buffer;
    int len;
    Connection *conn;
    long addr = 0;

    if (!ptr) pthread_exit(0);
    conn = (Connection *)ptr;

    // LOGIC OF APP
    while (1) {
        /* read length of message */
        read(conn->sock, &len, sizeof(int));
        if (len > 0) {
            addr = (long)((struct sockaddr_in *)&conn->address)->sin_addr.s_addr;
            buffer = (char *)malloc((len + 1) * sizeof(char));
            buffer[len] = 0;

            /* read message */
            read(conn->sock, buffer, len);

            /* print message */
            printf("%d.%d.%d.%d: %s\n", (int)((addr)&0xff), (int)((addr >> 8) & 0xff), (int)((addr >> 16) & 0xff), (int)((addr >> 24) & 0xff),
                   buffer);
            free(buffer);
        }
    }

    /* close socket and clean up */
    close(conn->sock);
    free(conn);
    pthread_exit(0);
}

int main(int argc, char **argv) {
    int sock_main_thread = -1;
    struct sockaddr_in address_server;
    int port;
    Connection *connection_to_client;
    pthread_t thread;

    /* check for command line arguments */
    if (argc != 2) {
        fprintf(stderr, "usage: %s port\n", argv[0]);
        return -1;
    }

    /* obtain port number */
    if (sscanf(argv[1], "%d", &port) <= 0) {
        fprintf(stderr, "%s: error: wrong parameter: port\n", argv[0]);
        return -2;
    }

    /* create socket */
    sock_main_thread = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_main_thread <= 0) {
        fprintf(stderr, "%s: error: cannot create socket\n", argv[0]);
        return -3;
    }

    /* bind socket to port */
    address_server.sin_family = AF_INET;
    address_server.sin_addr.s_addr = INADDR_ANY;
    address_server.sin_port = htons(port);
    if (bind(sock_main_thread, (struct sockaddr *)&address_server, sizeof(struct sockaddr_in)) < 0) {
        fprintf(stderr, "%s: error: cannot bind socket to port %d\n", argv[0], port);
        return -4;
    }

    /* listen on port */
    if (listen(sock_main_thread, BACKLOG_LISTEN_QUEUE) < 0) {
        fprintf(stderr, "%s: error: cannot listen on port\n", argv[0]);
        return -5;
    }
    // listen return 0 if ok
    printf("%s: ready and listening\n", argv[0]);

    while (1) {
        /* accept incoming connections */
        connection_to_client = (Connection *)malloc(sizeof(Connection));
        connection_to_client->sock = accept(sock_main_thread, &connection_to_client->address, &connection_to_client->addr_len);
        // check if accept has return a valid socketID
        if (connection_to_client->sock <= 0) {
            free(connection_to_client);
        } else {
            /* start a new thread but do not wait for it */
            pthread_create(&thread, 0, thread_handler_client, (void *)connection_to_client);
            pthread_detach(thread);
        }
    }

    return 0;
}