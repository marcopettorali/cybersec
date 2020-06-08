
#define NICKNAME_SERVER "server"
#define NONCE_32 32
#define CHALLENGE_32 32
#include"util.h"
#include"crypto.h"
#include <openssl/evp.h>

#ifndef MESSAGE_H
#define MESSAGE_H

typedef struct {
    char opcode;
    unsigned int payload_len;
    unsigned char* payload;
} Message;

typedef struct {
    char nickname_client[NICKNAME_LENGTH];
    char nickname_server[sizeof(NICKNAME_SERVER)];
    unsigned char nonce_client[NONCE_32];
    unsigned char challenge_to_client[CHALLENGE_32]; //WERE uns char *
    unsigned char challenge_to_server[CHALLENGE_32];
    unsigned char symmetric_key[GCM_KEY_SIZE]; //on 128 bit
    EVP_PKEY * server_pub_key;
    char expected_opcode;
} AuthenticationInstance;

#endif

//opcode                        
#define M1_CLIENT_SERVER_AUTH 100     // |100|len|ID_CLIENT ID_server NONCEa|
#define M2_CLIENT_SERVER_AUTH 101     // |101|len|Cs_len Cs EpubKa(ID_SERVER ID_CLIENT NONCEa CHallengeA) 
#define M3_CLIENT_SERVER_AUTH 102     // |102|len|EpubKServer(ID_CLIENT ID_SERVER CHallengeA CHallengeS Kas)
#define M4_CLIENT_SERVER_AUTH 103     // |103|len|EKas(ID_SERVER ID_CLIENT CHallengeS)   
#define SUCCESSFUL_CLIENT_SERVER_AUTH 104  //Expected from now on opcode > SUCCESSFUL_CLIENT_SERVER_AUTH


Message* create_M1_CLIENT_SERVER_AUTH(char* username_client, AuthenticationInstance * authInstance);
int handler_M1_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
Message* create_M2_CLIENT_SERVER_AUTH(AuthenticationInstance * authInstance);
int handler_M2_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,EVP_PKEY* prvkey);
bool get_and_verify_info_M2_CLIENT_SERVER_AUTH(unsigned char * plaintext,AuthenticationInstance* authInstance);
Message* create_M3_CLIENT_SERVER_AUTH(AuthenticationInstance * authInstance);
int handler_M3_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,EVP_PKEY* privkey);
bool get_and_verify_info_M3_CLIENT_SERVER_AUTH(unsigned char * plaintext,AuthenticationInstance* authInstance);
Message* create_M4_CLIENT_SERVER_AUTH(AuthenticationInstance * authInstance);
int handler_M4_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M4_CLIENT_SERVER_AUTH(unsigned char * plaintext,AuthenticationInstance* authInstance);


void free_MESSAGE(Message** mex);

//TO BE MOVED INTO pub_key_crypto.h
EVP_PKEY* get_and_verify_pub_key_from_certificate(AuthenticationInstance * authInstance);
EVP_PKEY* get_and_verify_pub_key_from_certificate_CLIENT_SIDE(X509* cert_server);
unsigned char* get_asymmetric_encrypted_digital_envelope(unsigned char* clear_buf, int clear_size, EVP_PKEY* pubkey, int* returning_size);
unsigned char* get_asymmetric_decrypted_digital_envelope(unsigned char* ciphertext_and_info_buf, int ciphertext_and_info_buf_size, EVP_PKEY* prvkey, int* returning_size);
bool server_authentication(EVP_PKEY** p_prvkey);
bool client_authentication(char* username_client,EVP_PKEY** p_prvkey);

//TO BE MOVED INTO crypto.h
void generate_symmetric_key(unsigned char **key,unsigned long key_len);