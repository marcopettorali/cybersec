#include "util.h"

#define MOVE_PAYLOAD_LEN 34
#define OPCODE_MOVE 126
#define ERROR 1
#define OK 0

int prepare_move_message(unsigned char* payload, char* player_n, char* opponent_n, char count, char column);
int extract_move_message(unsigned char* payload, char* player_1_ptr, char* player_2_ptr, char* count_ptr, char* column_ptr);
// void print_move_message(unsigned char* payload);
int send_move(char* player_n, char* opponent_n, char count, char column);
int wait_move(char* player_n, char* opponent_n, char* count, char* column);