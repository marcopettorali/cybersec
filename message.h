#define NICKNAME_SERVER "SERVER"
#define NONCE_32 32
#include"util.h"

typedef struct {
    int opcode;
    unsigned int payload_len;
    unsigned char* payload;
} Message;

typedef struct {
    char nickname_client[NICKNAME_LENGTH];
    char nickname_server[sizeof(NICKNAME_SERVER)];
    unsigned char* nonce_client[NONCE_32];
} AuthenticationInstance;


//opcode                        
#define M1_CLIENT_SERVER_AUTH 100     // |1|len|ID_CLIENT ID_server NONCE|


Message* create_M1_CLIENT_SERVER_AUTH(char* username_client);
int handler_M1_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);