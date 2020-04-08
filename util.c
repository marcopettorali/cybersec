#include "util.h"

void DEBUG(char* msg, const char* function) {
    printf("[DEBUG] In function %s(): %s\n", function, msg);
    return;
}
void EXCEPTION(char* msg, const char* function) {
    printf("[EXCEPTION] In function %s(): %s\n", function, msg);
    exit(EXIT_FAILURE);
}

void USER_WARNING(char* msg, const char* function) {
    printf("Warning: %s\n", function, msg);
}