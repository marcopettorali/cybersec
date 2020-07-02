#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OPCODE_SIZE 1
#define PAYLOAD_LEN_SIZE sizeof(int)
#define COUNTER_SIZE sizeof(int)

#define NICKNAME_LENGTH 16
#define PORT_FOR_GAMING 20200

#define MSG_SHOW_GUIDE_CLIENT_DASHBOARD -10
#define MSG_SHOW_GUIDE_CLIENT_SERVER_INTERACTION -11
#define MSG_SHOW_GUIDE_SERVER_CLIENT_COMMUNICATION -12

#define BACKLOG_LISTEN_QUEUE 50

void DEBUG(char* msg, const char* function);
void EXCEPTION(char* msg, const char* function);
void handle_msg(int msg);

void secure_input(char* buffer, size_t size);

#define COMMAND_SIZE 128
#define MSG_OK 1
#define MSG_COMMAND_NOT_FOUND 0
#define MSG_COLUMN_FULL -1
#define MSG_COLUMN_NOT_VALID -2
#define MSG_SHOW_GUIDE -3

#define RESET   "\033[0m"
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */