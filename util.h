#include <stdio.h>
#include <stdlib.h>

#define OPCODE_SIZE 1
#define PAYLOAD_LEN_SIZE sizeof(int)

#define NICKNAME_LENGTH 16
#define PORT_FOR_GAMING 20200

#define MSG_SHOW_GUIDE_CLIENT_DASHBOARD -10
#define MSG_SHOW_GUIDE_CLIENT_SERVER_INTERACTION -11
#define MSG_SHOW_GUIDE_SERVER_CLIENT_COMMUNICATION -12

#define BACKLOG_LISTEN_QUEUE 50

void DEBUG(char* msg, const char* function);
void EXCEPTION(char* msg, const char* function);