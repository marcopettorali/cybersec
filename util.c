#include "util.h"

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