#include "util.h"

int add_header(unsigned char* buffer, char opcode, int payload_len, unsigned char* payload);
int extract_header(unsigned char* buffer, char* opcode, int* payload_len, unsigned char* payload);
void print_header(unsigned char* buffer);