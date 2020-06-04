#include "util.h"
#include "game_util.h"

void handle_msg(int msg) {
    switch (msg) {
        case MSG_COLUMN_FULL:
            printf("Impossible to insert another checker in this column\n");
            break;
        case MSG_COMMAND_NOT_FOUND:
            printf("command not recognized. Type 'help' for a list of commands\n");
            break;
        case MSG_COLUMN_NOT_VALID:
            printf("inserted column is not valid. You have to insert a number between 0 and 6\n");
            break;
        case MSG_SHOW_GUIDE:
            printf("GUIDE:\n");
            printf("insert c:\tinserts a checker in the specified column c\n");
            printf("help\t:\tshows this guide\n");
            printf("quit\t:\tquit the game\n");
            break;
        case MSG_SHOW_GUIDE_CLIENT_DASHBOARD:
            printf("GUIDE:\n");
            printf("server\t:\tconnect to server\n");
            printf("help\t:\tshows this guide\n");
            printf("quit\t:\tquit the program\n");
            break;
        case MSG_SHOW_GUIDE_CLIENT_SERVER_INTERACTION:
            printf("GUIDE:\n");
            printf("chat\t:\tchat with the server\n");
            printf("list\t:\tretrive the list of active users from the server\n");
            printf("play\t:\tconnect p2p to a client retrived from the server\n");
            printf("help\t:\tshows this guide\n");
            printf("close\t:\tclose the connection with the server\n");
            break;
        }
}

void DEBUG(char* msg, const char* function) {
    printf("[DEBUG] In function %s(): %s\n", function, msg);
    return;
}
void EXCEPTION(char* msg, const char* function) {
    printf("[EXCEPTION] In function %s(): %s\n", function, msg);
    exit(EXIT_FAILURE);
}