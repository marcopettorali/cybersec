#include <stdio.h>
#include <stdlib.h>

#define GRID_WIDTH 7
#define GRID_HEIGHT 6
#define COMMAND_SIZE 128

#define PLAYER 1
#define NO_PLAYER 0
#define OPPONENT -1

#define MSG_OK 1
#define MSG_COMMAND_NOT_FOUND 0
#define MSG_COLUMN_FULL -1
#define MSG_COLUMN_NOT_VALID -2
#define MSG_SHOW_GUIDE -3

#define MSG_SHOW_GUIDE_CLIENT_DASHBOARD -10
#define MSG_SHOW_GUIDE_CLIENT_SERVER_INTERACTION -11

#define BACKLOG_LISTEN_QUEUE 50

void handle_msg(int msg);

void DEBUG(char* msg, const char* function);
void EXCEPTION(char* msg, const char* function);