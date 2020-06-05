#include "net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int add_header(unsigned char* buffer, char opcode, int payload_len, unsigned char* payload) {
    // initializing the index in the buffer
    int byte_index = 0;

    // creating header: opcode
    char* opcode_ptr = (char*)&buffer[byte_index];
    *opcode_ptr = opcode;
    byte_index += OPCODE_SIZE;

    // creating header: payload_len
    int* payload_len_ptr = (int*)&buffer[byte_index];
    *payload_len_ptr = payload_len;
    byte_index += PAYLOAD_LEN_SIZE;

    // adding the payload
    memcpy(&buffer[byte_index], payload, payload_len);
    byte_index += payload_len;

    return byte_index;
}

int extract_header(unsigned char* buffer, char* opcode, int* payload_len, unsigned char* payload) {
    // initializing the index in the buffer
    int byte_index = 0;

    // creating header: opcode
    char* opcode_ptr = (char*)&buffer[byte_index];
    *opcode = *opcode_ptr;
    byte_index += OPCODE_SIZE;

    // creating header: payload_len
    int* payload_len_ptr = (int*)&buffer[byte_index];
    *payload_len = *payload_len_ptr;
    byte_index += PAYLOAD_LEN_SIZE;

    // adding the payload
    memcpy(payload, &buffer[byte_index], *payload_len);

    byte_index += *payload_len;

    return byte_index;
}

void print_header(unsigned char* buffer) {
    int byte_index = 0;

    char* opcode_ptr = (char*)&buffer[byte_index];
    printf("[%d", *opcode_ptr);
    byte_index += OPCODE_SIZE;

    int* payload_len = (int*)&buffer[byte_index];
    printf("|%d]", *payload_len);
    byte_index += PAYLOAD_LEN_SIZE;

    printf("\n");
}