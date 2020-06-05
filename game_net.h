#include "util.h"

#define MOVE_PAYLOAD_LEN 34
#define OPCODE_MOVE 1

// to be filled as soon as possible in the protocol, before playing
// we can move them to another file
extern char player_nickname[NICKNAME_LENGTH];
extern char opponent_nickname[NICKNAME_LENGTH];

int prepare_move_message(unsigned char* payload, char* player_1, char* player_2, char count, char column);
int extract_move_message(unsigned char* payload, char* player_1_ptr, char* player_2_ptr, char* count_ptr, char* column_ptr);
void print_move_message(unsigned char* payload);
int send_move(char* player_1, char* player_2, char count, char column);