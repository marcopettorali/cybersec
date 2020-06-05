
typedef struct {
    int opcode;
    unsigned int payload_len;
    char* payload;
} Message;


#define NICKNAME_SERVER 6
#define NONCE_32 32

//opcode                        
#define M1_CLIENT_SERVER_AUTH 1     // |1|len|ID_CLIENT ID_server NONCE|


Message* create_M1_CLIENT_SERVER_AUTH(char* username_client);