#include "game_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "game_util.h"
#include "net.h"
#include "util.h"

int prepare_move_message(unsigned char* payload, char* player_1, char* player_2, char count, char column) {
    // initializing the index in the buffer
    int byte_index = 0;

    // writing this player's username
    strncpy(&payload[byte_index], player_1, NICKNAME_LENGTH);
    byte_index += NICKNAME_LENGTH;

    // writing the opponent's username
    strncpy(&payload[byte_index], player_2, NICKNAME_LENGTH);
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

    strncpy(&player_1_ptr[0], &payload[byte_index], NICKNAME_LENGTH);
    byte_index += NICKNAME_LENGTH;

    strncpy(&player_2_ptr[0], &payload[byte_index], NICKNAME_LENGTH);
    byte_index += NICKNAME_LENGTH;

    count_ptr = &payload[byte_index];
    byte_index += sizeof(char);

    column_ptr = &payload[byte_index];
    byte_index += sizeof(char);

    printf("\n");
}

void print_move_message(unsigned char* payload) {
    int byte_index = 0;

    char player_1[NICKNAME_LENGTH];
    strncpy(&player_1[0], &payload[byte_index], NICKNAME_LENGTH);
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
}

int send_move(char* player_1, char* player_2, char count, char column) {
    unsigned char* payload = (unsigned char*)malloc(MOVE_PAYLOAD_LEN);
    prepare_move_message(&payload[0], player_nickname, opponent_nickname, count, column);
    unsigned char* plaintext = (unsigned char*)malloc(OPCODE_SIZE + PAYLOAD_LEN_SIZE + MOVE_PAYLOAD_LEN);
    add_header(&plaintext[0], OPCODE_MOVE, MOVE_PAYLOAD_LEN, &payload[0]);
    unsigned char* ciphertext = (unsigned char*)malloc(GCM_AAD_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE + OPCODE_SIZE + PAYLOAD_LEN_SIZE + MOVE_PAYLOAD_LEN);
    prepare_gcm_ciphertext(&plaintext[0], OPCODE_SIZE + PAYLOAD_LEN_SIZE + MOVE_PAYLOAD_LEN, &ciphertext[0], &shared_key[0]);
    // TODO: IMPLEMENT SEND!!!
}

int wait_move(char* player_1, char* player_2, char* count, char* column) {
    unsigned char* ciphertext = (unsigned char*)malloc(GCM_AAD_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE + OPCODE_SIZE + PAYLOAD_LEN_SIZE + MOVE_PAYLOAD_LEN);
    // TODO: IMPLEMENT RECEIVE (into the ciphertext)!!!
    unsigned char* plaintext = (unsigned char*)malloc(OPCODE_SIZE + PAYLOAD_LEN_SIZE + MOVE_PAYLOAD_LEN);
    extract_gcm_ciphertext(&ciphertext[0], GCM_AAD_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE + OPCODE_SIZE + PAYLOAD_LEN_SIZE + MOVE_PAYLOAD_LEN,
                           &plaintext[0], &shared_key[0]);

    char opcode;
    int payload_len;
    unsigned char* payload = (unsigned char*)malloc(MOVE_PAYLOAD_LEN);

    extract_header(&plaintext[0], &opcode, &payload_len, &payload[0]);

    if (opcode != OPCODE_MOVE) {
        printf("error: opcode = %d\n", opcode);
        EXCEPTION("OPCODE DOESN'T MATCH", __func__);
    }

    if (payload_len != MOVE_PAYLOAD_LEN) {
        printf("error: move payload len = %d\n", MOVE_PAYLOAD_LEN);
        EXCEPTION("MOVE PAYLOAD LEN DOESN'T MATCH", __func__);
    }

    extract_move_message(&payload[0], &player_1[0], &player_2[0], count, column);
}

int main() {
    unsigned char* payload = (unsigned char*)malloc(MOVE_PAYLOAD_LEN);
    char gino_str[NICKNAME_LENGTH];
    char pino_str[NICKNAME_LENGTH];

    strncpy(gino_str, "Gino", NICKNAME_LENGTH);
    strncpy(pino_str, "Pino", NICKNAME_LENGTH);

    prepare_move_message(payload, &gino_str[0], &pino_str[0], 2, 4);
    print_move_message(payload);

    unsigned char* buffer = (unsigned char*)malloc(OPCODE_SIZE + PAYLOAD_LEN_SIZE + MOVE_PAYLOAD_LEN);
    add_header(&buffer[0], OPCODE_MOVE, MOVE_PAYLOAD_LEN, &payload[0]);

    char opcode;
    int payload_len;
    unsigned char* payload_rcv = (unsigned char*)malloc(MOVE_PAYLOAD_LEN);
    extract_header(&buffer[0], &opcode, &payload_len, &payload_rcv[0]);
    print_header(&buffer[0]);
    print_move_message(&payload_rcv[0]);
}