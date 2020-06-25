#include "game_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "crypto.h"
#include "game_util.h"
#include "message.h"
#include "net.h"
#include "util.h"

// parameters passed by client's main
extern char* player_nick;
extern char* opponent_nick;
unsigned char* key;
int sock;

int prepare_move_message(unsigned char* payload, char* player_n, char* opponent_n, char count, char column) {
    printf("player = %s, opponent = %s, count = %d, column = %d\n", player_nick, opponent_nick, count, column);
    // initializing the index in the buffer
    int byte_index = 0;

    // writing this player's username
    memcpy(&payload[byte_index], player_n, NICKNAME_LENGTH);
    byte_index += NICKNAME_LENGTH;

    // writing the opponent's username
    memcpy(&payload[byte_index], opponent_n, NICKNAME_LENGTH);
    byte_index += NICKNAME_LENGTH;

    // writing the counter
    payload[byte_index] = count;
    byte_index += sizeof(char);

    // writing the column
    payload[byte_index] = column;
    byte_index += sizeof(char);

    return byte_index;
}

int extract_move_message(unsigned char* payload, char* player_1_ptr, char* player_2_ptr, char* count_ptr, char* column_ptr) {
    int byte_index = 0;

    memcpy(&player_1_ptr[0], &payload[byte_index], NICKNAME_LENGTH);
    byte_index += NICKNAME_LENGTH;

    memcpy(&player_2_ptr[0], &payload[byte_index], NICKNAME_LENGTH);
    byte_index += NICKNAME_LENGTH;

    *count_ptr = payload[byte_index];
    byte_index += sizeof(char);

    *column_ptr = payload[byte_index];
    byte_index += sizeof(char);

    return OK;
}

/*void print_move_message(unsigned char* payload) {
    int byte_index = 0;

    char player_1[NICKNAME_LENGTH];
    memcpy(&player_1[0], &payload[byte_index], NICKNAME_LENGTH);
    printf("|%s", player_1);
    byte_index += NICKNAME_LENGTH;

    char player_2[NICKNAME_LENGTH];
    strncpy(&player_2[0], &payload[byte_index], NICKNAME_LENGTH);
    printf("|%s", player_2);
    byte_index += NICKNAME_LENGTH;

    char* count_ptr = &payload[byte_index];
    printf("|%d", *count_ptr);
    byte_index += sizeof(char);

    char* column_ptr = &payload[byte_index];
    printf("|%d]", *column_ptr);
    byte_index += sizeof(char);

    printf("\n");

    // Need to know if waste of char after effective nickname
    BIO_dump_fp(stdout, (const char*)payload, byte_index);
}*/

int send_move(char* player_n, char* opponent_n, char count, char column) {
    unsigned char* payload = (unsigned char*)malloc(MOVE_PAYLOAD_LEN);
    prepare_move_message(&payload[0], &player_n[0], &opponent_n[0], count, column);
    unsigned char* plaintext = (unsigned char*)malloc(OPCODE_SIZE + PAYLOAD_LEN_SIZE + MOVE_PAYLOAD_LEN);
    add_header(&plaintext[0], OPCODE_MOVE, MOVE_PAYLOAD_LEN, &payload[0]);
    int ciphertext_len;
    unsigned char* ciphertext = prepare_gcm_ciphertext(&plaintext[0], OPCODE_SIZE + PAYLOAD_LEN_SIZE + MOVE_PAYLOAD_LEN, &key[0], &ciphertext_len);
    int byte_correctly_sent = send(sock, &ciphertext[0], ciphertext_len, 0);
    printf("Sent move: player = %s, opponent = %s , count = %d, column = %d\n", player_n, opponent_n, count, column);
    return byte_correctly_sent == ciphertext_len ? 1 : 0;
}

int wait_move(char* player_n, char* opponent_n, char* count, char* column) {
    int wait_move_packet_size = GCM_AAD_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE + OPCODE_SIZE + PAYLOAD_LEN_SIZE + MOVE_PAYLOAD_LEN;
    unsigned char* ciphertext = (unsigned char*)malloc(wait_move_packet_size);

    int read_byte = read(sock, &ciphertext[0], wait_move_packet_size);

    if (read_byte != wait_move_packet_size) {
        printf("error: bytes read = %d, bytes expected = %d\n", read_byte, wait_move_packet_size);
        return ERROR;
    }

    int plaintext_len;
    unsigned char* plaintext = extract_gcm_ciphertext(&ciphertext[0], wait_move_packet_size, &key[0], &plaintext_len);

    free(ciphertext);

    char opcode;
    int payload_len;
    unsigned char* payload = (unsigned char*)malloc(MOVE_PAYLOAD_LEN);

    extract_header(&plaintext[0], &opcode, &payload_len, &payload[0]);

    if (opcode != OPCODE_MOVE) {
        printf("error: opcode = %d\n", opcode);
        return ERROR;
    }

    if (payload_len != MOVE_PAYLOAD_LEN) {
        printf("error: move payload len = %d\n", MOVE_PAYLOAD_LEN);
        return ERROR;
    }

    extract_move_message(&payload[0], &player_n[0], &opponent_n[0], count, column);

    printf("Received move: player = %s, opponent = %s , count = %d, column = %d\n", player_n, opponent_n, *count, *column);

    return OK;
}