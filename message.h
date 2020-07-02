#include <openssl/evp.h>
#include <stdbool.h>

#include "crypto.h"
#include "list.h"
#include "util.h"

#ifndef MESSAGE_H
#define MESSAGE_H

#define NICKNAME_SERVER "server"
#define NONCE_32 32
#define CHALLENGE_32 32

typedef struct {
    char opcode;
    unsigned int payload_len;
    unsigned char* payload;
} Message;

typedef struct {
    char nickname_client[NICKNAME_LENGTH];
    char nickname_server[sizeof(NICKNAME_SERVER)];
    unsigned char nonce_client[NONCE_32];
    unsigned char challenge_to_client[CHALLENGE_32];  // WERE uns char *
    unsigned char challenge_to_server[CHALLENGE_32];
    unsigned char symmetric_key[GCM_KEY_SIZE];  // on 128 bit
    EVP_PKEY* server_pub_key;
    char expected_opcode;
    char nickname_opponent_required[NICKNAME_LENGTH];  // NEEDED for playing
    unsigned char nonce_server[NONCE_32];              // NEEDED for playing
    
    int counter; //TO AVOID REPLAY ATTACK
    EVP_PKEY *my_dh_private_key;
    EVP_PKEY *peer_dh_pub_key;
    EVP_PKEY* client_pub_key;
} AuthenticationInstance;

typedef struct {
    char nickname_local[NICKNAME_LENGTH];
    char nickname_opponent[NICKNAME_LENGTH];
    unsigned char nonce_local[NONCE_32];
    unsigned char nonce_opponent[NONCE_32];
    unsigned char challenge_to_local[CHALLENGE_32];
    unsigned char challenge_to_opponent[CHALLENGE_32];
    unsigned char symmetric_key[GCM_KEY_SIZE];  // on 128 bit
    EVP_PKEY* opponent_pub_key;
    EVP_PKEY* local_priv_key;
    char expected_opcode;

    int counter; //TO AVOID REPLAY ATTACK
    char nickname_master[NICKNAME_LENGTH];
    char nickname_slave[NICKNAME_LENGTH];
    unsigned char challenge_to_slave[CHALLENGE_32];
    unsigned char challenge_to_master[CHALLENGE_32];
    EVP_PKEY *my_dh_private_key;
    EVP_PKEY *peer_dh_pub_key;
} AuthenticationInstanceToPlay;

#endif

// opcode
#define M1_CLIENT_SERVER_AUTH 100          // |100|len|ID_CLIENT ID_server Challenge_S|
#define M2_CLIENT_SERVER_AUTH 101          // |101|len|Cs_len Cs Challenge_A ID_SERVER ID_CLIENT Challenge_S Yserv Sign_size EprivKeyServer(ID_SERVER ID_CLIENT Challenge_S Yserv) //send the mex also in clear, then verify
#define M3_CLIENT_SERVER_AUTH 102          // |102|len|ID_CLIENT ID_SERVER Challenge_A Yclient_len Yclient Sign_size EprivKeyClient(ID_CLIENT ID_SERVER Challenge_A Yclient_len Yclient)|
#define M4_CLIENT_SERVER_AUTH 103          // |103|len|EKas(ID_SERVER ID_CLIENT)
#define M5_CLIENT_SERVER_AUTH 60           // |103|len|EKas(ID_SERVER ID_CLIENT)
#define SUCCESSFUL_CLIENT_SERVER_AUTH 104  // Expected from now on opcode > SUCCESSFUL_CLIENT_SERVER_AUTH

#define M_LISTEN_PORT_CLIENT_P2P 105  // |106|len|EKas(ID_CLIENT ID_SERVER PORT) //No worry about replay since for definition only once sent
#define SUCCESSFUL_CLIENT_AUTHENTICATION_AND_CONFIGURATION 106

#define M_REQ_LIST 107  // |107|len|EKas(NONCE_CLIENT) //NO ID_CLIENT ID_SERVER since Kas already link this two entities
#define M_RES_LIST 108  // |108|len|EKas(NONCE_CLIENT list) //NO ID_CLIENT ID_SERVER since Kas already link this two entities

#define M_REQ_PLAY 109  // |109|len|EKas(ID_OPPONENT NONCE_CLIENT) //Nonce client is to avoid replay of requests (so to be forced to play always with the same opponent) //to ensure freshness of server's response
#define M_RES_PLAY_TO_ACK 110  // |110|len|EKas(ID_OPPONENT NONCE_CLIENT NONCE_SERVER) //Nonce server is to ensure freshness from server side (otherwise if already requested to play an enemy could force the same player to play always with the prevoius target)
#define M_RES_PLAY_ACK 111  // |111|len|EKas(ID_OPPONENT NONCE_SERVER) //to prove freshness to server
#define M_REQ_ACCEPT_PLAY_TO_ACK 112  // |112|len|EKas(ID_OPPONENT NONCE_SERVER) //ask the guest if he wants to pla with ID_OPPONENT //to prove freshness to server 
#define M_RES_ACCEPT_PLAY_ACK 113  // |113|len|EKas(RESPONSE_1BYTE ID_OPPONENT NONCE_SERVER)
#define M_RES_PLAY_OPPONENT 114  // |114|len|EKas(RESPONSE_1BYTE OPPONENT_PORT(INT) ID_OPPONENT NONCE_CLIENT) //real answer of M_REQ_PLAY

#define M_PRELIMINARY_INFO_OPPONENT 30  // |30|len|EKas(ID_LOCAL ID_OPPONENT PUBkeyOPPONENT)|

#define M1_INFORM_SERVER_GAME_START 115  // |115|len|EKas(NONCE_CLIENT) //NONCE_CLIENT will be send againg by client to avoid replay attack to inform erroneously the server about the ending of the game
#define M2_INFORM_SERVER_GAME_START 116  // |116|len|EKas(NONCE_CLIENT NONCE_SERVER) //server->client
#define M3_INFORM_SERVER_GAME_START 117  // |116|len|EKas(NONCE_SERVER) //client->server for freshness

#define M1_INFORM_SERVER_GAME_END 118  // |115|len|EKas(NONCE_CLIENT) //client->server
#define M2_INFORM_SERVER_GAME_END 119  // |116|len|EKas(NONCE_CLIENT NONCE_SERVER) //server->client
#define M3_INFORM_SERVER_GAME_END 120  // |116|len|EKas(NONCE_SERVER) //client->server for freshness

#define M1_CLIENT_CLIENT_AUTH 121  // |121|len|ID_MASTER ID_SLAVE CHALLENGE_S|  |ID_MASTER ID_SLAVE CHALLENGE_SLAVE|
#define M2_CLIENT_CLIENT_AUTH 122  // |122|len|Challenge_M ID_SLAVE ID_MASTER Challenge_S Yslave_len Yslave Sign_size EprivKeyServer(ID_SLAVE ID_MASTER Challenge_S Yslave_len Yslave)
#define M3_CLIENT_CLIENT_AUTH 123  // |123|len|ID_CLIENT ID_SERVER Challenge_A Yclient_len Yclient Sign_size EprivKeyClient(ID_CLIENT ID_SERVER Challenge_A Yclient_len Yclient)|
#define M4_CLIENT_CLIENT_AUTH 124  // |124|len|EKas(ID_MASTER ID_CLIENT)
#define M5_CLIENT_CLIENT_AUTH 40  //  |40 |len|EKas(ID_MASTER ID_CLIENT)
#define SUCCESSFUL_CLIENT_CLIENT_AUTH 125

#define M_CLOSE 126  // |120|len|EKas(Kas) //No worry about replay since for definition only once sent (Kas is to add something otherwise if only opcode everybody could send it to ruin the game)

Message* create_M1_CLIENT_SERVER_AUTH(char* username_client, AuthenticationInstance* authInstance);
int handler_M1_CLIENT_SERVER_AUTH(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance);
Message* create_M2_CLIENT_SERVER_AUTH(AuthenticationInstance* authInstance, EVP_PKEY* privkey);
int handler_M2_CLIENT_SERVER_AUTH(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance, EVP_PKEY* prvkey);
bool get_and_verify_info_M2_CLIENT_SERVER_AUTH(unsigned char* plaintext, AuthenticationInstance* authInstance);
Message* create_M3_CLIENT_SERVER_AUTH(AuthenticationInstance* authInstance, EVP_PKEY * privkey);
int handler_M3_CLIENT_SERVER_AUTH(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance, EVP_PKEY* privkey);
bool get_and_verify_info_M3_CLIENT_SERVER_AUTH(unsigned char* plaintext, AuthenticationInstance* authInstance);
Message* create_M4_CLIENT_SERVER_AUTH(AuthenticationInstance* authInstance);
int handler_M4_CLIENT_SERVER_AUTH(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance);
bool get_and_verify_info_M4_CLIENT_SERVER_AUTH(unsigned char* plaintext, AuthenticationInstance* authInstance);
Message* create_M5_CLIENT_SERVER_AUTH(AuthenticationInstance* authInstance);
int handler_M5_CLIENT_SERVER_AUTH(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance);
bool get_and_verify_info_M5_CLIENT_SERVER_AUTH(unsigned char* plaintext, AuthenticationInstance* authInstance);

Message* create_M_LISTEN_PORT_CLIENT_P2P(int port, AuthenticationInstance* authInstance);
int handler_M_LISTEN_PORT_CLIENT_P2P(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance, int* port);
bool get_and_verify_info_M_LISTEN_PORT_CLIENT_P2P(unsigned char* plaintext, AuthenticationInstance* authInstance, int* port);

Message* create_M_REQ_LIST(AuthenticationInstance* authInstance);
int handler_M_REQ_LIST(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance);
bool get_and_verify_info_M_REQ_LIST(unsigned char* plaintext, AuthenticationInstance* authInstance);
Message* create_M_RES_LIST(AuthenticationInstance* authInstance, struct node* head_of_list_users, int user_counter, pthread_mutex_t mutex_list_users);
int handler_M_RES_LIST(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance, char** list_buffer);
bool get_and_verify_info_M_RES_LIST(unsigned char* plaintext, int plaintext_size, AuthenticationInstance* authInstance, char** list_buffer);

Message* create_M_REQ_PLAY(char* username_opponent, AuthenticationInstance* authInstance);
int handler_M_REQ_PLAY(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance);
bool get_and_verify_info_M_REQ_PLAY(unsigned char* plaintext, AuthenticationInstance* authInstance);
Message* create_M_RES_PLAY_TO_ACK(AuthenticationInstance* authInstance);
int handler_M_RES_PLAY_TO_ACK(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance);
bool get_and_verify_info_M_RES_PLAY_TO_ACK(unsigned char* plaintext, AuthenticationInstance* authInstance);
Message* create_M_RES_PLAY_ACK(AuthenticationInstance* authInstance);
int handler_M_RES_PLAY_ACK(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance);
bool get_and_verify_info_M_RES_PLAY_ACK(unsigned char* plaintext, AuthenticationInstance* authInstance);

Message* create_M_REQ_ACCEPT_PLAY_TO_ACK(char* username_opponent, AuthenticationInstance* authInstance);  // from master: to ask guest if wants to
                                                                                                          // play
int handler_M_REQ_ACCEPT_PLAY_TO_ACK(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance);
bool get_and_verify_info_M_REQ_ACCEPT_PLAY_TO_ACK(unsigned char* plaintext, AuthenticationInstance* authInstance);
Message* create_M_RES_ACCEPT_PLAY_ACK(char answer, AuthenticationInstance* authInstance);  // from slave: to answer the server if wants to play
int handler_M_RES_ACCEPT_PLAY_ACK(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance, char* answer);
bool get_and_verify_info_M_RES_ACCEPT_PLAY_ACK(unsigned char* plaintext, AuthenticationInstance* authInstance, char* answer);
Message* create_M_RES_PLAY_OPPONENT(char answer, int opponent_port,
                                    AuthenticationInstance* authInstance);  // to master: to answer if he has accepted to play
int handler_M_RES_PLAY_OPPONENT(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance, char* answer, int* opponent_port);
bool get_and_verify_info_M_RES_PLAY_OPPONENT(unsigned char* plaintext, AuthenticationInstance* authInstance, char* answer, int* opponent_port);

Message* create_M_INFORM_SERVER_GAME_START(AuthenticationInstance* authInstance);
int handler_M_INFORM_SERVER_GAME_START(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance);
bool get_and_verify_info_M_INFORM_SERVER_GAME_START(unsigned char* plaintext, AuthenticationInstance* authInstance);
Message* create_M_INFORM_SERVER_GAME_END(AuthenticationInstance* authInstance);
int handler_M_INFORM_SERVER_GAME_END(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance);
bool get_and_verify_info_M_INFORM_SERVER_GAME_END(unsigned char* plaintext, AuthenticationInstance* authInstance);

Message* create_M_PRELIMINARY_INFO_OPPONENT(EVP_PKEY* opponent_pub_key, AuthenticationInstance* authInstance);  // from server
int handler_M_PRELIMINARY_INFO_OPPONENT(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance, AuthenticationInstanceToPlay* authInstanceToPlay);
bool get_and_verify_info_M_PRELIMINARY_INFO_OPPONENT(unsigned char* plaintext, AuthenticationInstance* authInstance, AuthenticationInstanceToPlay* authInstanceToPlay);

Message* create_M_CLOSE(AuthenticationInstance* authInstance);
int handler_M_CLOSE(unsigned char* payload, unsigned int payload_len, AuthenticationInstance* authInstance);
bool get_and_verify_info_M_CLOSE(unsigned char* plaintext, AuthenticationInstance* authInstance);

// CODICE_MARCO_BEGIN

Message* create_M1_CLIENT_CLIENT_AUTH(AuthenticationInstanceToPlay* authInstanceToPlay);
int handler_M1_CLIENT_CLIENT_AUTH(unsigned char* payload, unsigned int payload_len, AuthenticationInstanceToPlay* authInstanceToPlay);
bool get_and_verify_info_M1_CLIENT_CLIENT_AUTH(unsigned char* plaintext, AuthenticationInstanceToPlay* authInstance);

Message* create_M2_CLIENT_CLIENT_AUTH(AuthenticationInstanceToPlay* authInstanceToPlay);
int handler_M2_CLIENT_CLIENT_AUTH(unsigned char* payload, unsigned int payload_len, AuthenticationInstanceToPlay* authInstanceToPlay, EVP_PKEY* prvkey);
bool get_and_verify_info_M2_CLIENT_CLIENT_AUTH(unsigned char* plaintext, AuthenticationInstanceToPlay* authInstance);

Message* create_M3_CLIENT_CLIENT_AUTH(AuthenticationInstanceToPlay* authInstance);
int handler_M3_CLIENT_CLIENT_AUTH(unsigned char* payload, unsigned int payload_len, AuthenticationInstanceToPlay* authInstance, EVP_PKEY* privkey);
bool get_and_verify_info_M3_CLIENT_CLIENT_AUTH(unsigned char* plaintext, AuthenticationInstanceToPlay* authInstance);

Message* create_M4_CLIENT_CLIENT_AUTH(AuthenticationInstanceToPlay* authInstance);
int handler_M4_CLIENT_CLIENT_AUTH(unsigned char* payload, unsigned int payload_len, AuthenticationInstanceToPlay* authInstance);
bool get_and_verify_info_M4_CLIENT_CLIENT_AUTH(unsigned char* plaintext, AuthenticationInstanceToPlay* authInstance);

Message* create_M5_CLIENT_CLIENT_AUTH(AuthenticationInstanceToPlay* authInstance);
int handler_M5_CLIENT_CLIENT_AUTH(unsigned char* payload, unsigned int payload_len, AuthenticationInstanceToPlay* authInstance);
bool get_and_verify_info_M5_CLIENT_CLIENT_AUTH(unsigned char* plaintext, AuthenticationInstanceToPlay* authInstance);

// CODICE_MARCO_END

Message* create_M1_CLIENT_SERVER_AUTH(char* username_client, AuthenticationInstance * authInstance);
int handler_M1_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);

int handler_M2_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,EVP_PKEY* prvkey);
bool get_and_verify_info_M2_CLIENT_SERVER_AUTH(unsigned char * plaintext,AuthenticationInstance* authInstance);
int handler_M3_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,EVP_PKEY* privkey);
bool get_and_verify_info_M3_CLIENT_SERVER_AUTH(unsigned char * plaintext,AuthenticationInstance* authInstance);
Message* create_M4_CLIENT_SERVER_AUTH(AuthenticationInstance * authInstance);
int handler_M4_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M4_CLIENT_SERVER_AUTH(unsigned char * plaintext,AuthenticationInstance* authInstance);

Message* create_M_LISTEN_PORT_CLIENT_P2P(int port, AuthenticationInstance * authInstance);
int handler_M_LISTEN_PORT_CLIENT_P2P(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance, int* port);
bool get_and_verify_info_M_LISTEN_PORT_CLIENT_P2P(unsigned char * plaintext,AuthenticationInstance* authInstance, int* port);

Message* create_M_REQ_LIST(AuthenticationInstance * authInstance);
int handler_M_REQ_LIST(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M_REQ_LIST(unsigned char * plaintext,AuthenticationInstance* authInstance);
Message* create_M_RES_LIST(AuthenticationInstance * authInstance,struct node* head_of_list_users,int user_counter, pthread_mutex_t mutex_list_users);
int handler_M_RES_LIST(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance, char** list_buffer);
bool get_and_verify_info_M_RES_LIST(unsigned char * plaintext,int plaintext_size,AuthenticationInstance* authInstance, char** list_buffer);

Message* create_M_REQ_PLAY(char* username_opponent, AuthenticationInstance * authInstance);
int handler_M_REQ_PLAY(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M_REQ_PLAY(unsigned char * plaintext,AuthenticationInstance* authInstance);
Message* create_M_RES_PLAY_TO_ACK(AuthenticationInstance * authInstance);
int handler_M_RES_PLAY_TO_ACK(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M_RES_PLAY_TO_ACK(unsigned char * plaintext,AuthenticationInstance* authInstance);
Message* create_M_RES_PLAY_ACK(AuthenticationInstance * authInstance);
int handler_M_RES_PLAY_ACK(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M_RES_PLAY_ACK(unsigned char * plaintext,AuthenticationInstance* authInstance);

Message* create_M_REQ_ACCEPT_PLAY_TO_ACK(char* username_opponent, AuthenticationInstance * authInstance); //from master: to ask guest if wants to play
int handler_M_REQ_ACCEPT_PLAY_TO_ACK(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M_REQ_ACCEPT_PLAY_TO_ACK(unsigned char * plaintext,AuthenticationInstance* authInstance);
Message* create_M_RES_ACCEPT_PLAY_ACK(char answer, AuthenticationInstance * authInstance); //from slave: to answer the server if wants to play
int handler_M_RES_ACCEPT_PLAY_ACK(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,char* answer);
bool get_and_verify_info_M_RES_ACCEPT_PLAY_ACK(unsigned char * plaintext,AuthenticationInstance* authInstance,char* answer);
Message* create_M_RES_PLAY_OPPONENT(char answer,int opponent_port, AuthenticationInstance * authInstance); //to master: to answer if he has accepted to play
int handler_M_RES_PLAY_OPPONENT(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,char* answer,int* opponent_port);
bool get_and_verify_info_M_RES_PLAY_OPPONENT(unsigned char * plaintext,AuthenticationInstance* authInstance,char* answer,int* opponent_port);

Message* create_M1_INFORM_SERVER_GAME_START(AuthenticationInstance * authInstance);
int handler_M1_INFORM_SERVER_GAME_START(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M1_INFORM_SERVER_GAME_START(unsigned char * plaintext,AuthenticationInstance* authInstance);
Message* create_M2_INFORM_SERVER_GAME_START(AuthenticationInstance * authInstance);
int handler_M2_INFORM_SERVER_GAME_START(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M2_INFORM_SERVER_GAME_START(unsigned char * plaintext,AuthenticationInstance* authInstance);
Message* create_M3_INFORM_SERVER_GAME_START(AuthenticationInstance * authInstance);
int handler_M3_INFORM_SERVER_GAME_START(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M3_INFORM_SERVER_GAME_START(unsigned char * plaintext,AuthenticationInstance* authInstance);

Message* create_M1_INFORM_SERVER_GAME_END(AuthenticationInstance * authInstance);
int handler_M1_INFORM_SERVER_GAME_END(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M1_INFORM_SERVER_GAME_END(unsigned char * plaintext,AuthenticationInstance* authInstance);
Message* create_M2_INFORM_SERVER_GAME_END(AuthenticationInstance * authInstance);
int handler_M2_INFORM_SERVER_GAME_END(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M2_INFORM_SERVER_GAME_END(unsigned char * plaintext,AuthenticationInstance* authInstance);
Message* create_M3_INFORM_SERVER_GAME_END(AuthenticationInstance * authInstance);
int handler_M3_INFORM_SERVER_GAME_END(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M3_INFORM_SERVER_GAME_END(unsigned char * plaintext,AuthenticationInstance* authInstance);

Message* create_M_PRELIMINARY_INFO_OPPONENT(EVP_PKEY * opponent_pub_key, AuthenticationInstance * authInstance); //from server
int handler_M_PRELIMINARY_INFO_OPPONENT(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,AuthenticationInstanceToPlay * authInstanceToPlay);
bool get_and_verify_info_M_PRELIMINARY_INFO_OPPONENT(unsigned char * plaintext,AuthenticationInstance* authInstance,AuthenticationInstanceToPlay * authInstanceToPlay);

Message* create_M_CLOSE(AuthenticationInstance * authInstance);
int handler_M_CLOSE(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance);
bool get_and_verify_info_M_CLOSE(unsigned char * plaintext,AuthenticationInstance* authInstance);


Message* create_M1_CLIENT_CLIENT_AUTH(AuthenticationInstanceToPlay * authInstanceToPlay);
int handler_M1_CLIENT_CLIENT_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstanceToPlay * authInstanceToPlay);




bool send_MESSAGE(int sock, Message* mex);
bool read_MESSAGE(int sock, Message* mex_received);
bool read_MESSAGE_payload(int sock, Message* mex_received);
void free_MESSAGE(Message** mex);
void reformat_nickname(char* nick);

// TO BE MOVED INTO pub_key_crypto.h
EVP_PKEY* get_and_verify_pub_key_from_certificate(char* nickname_client);
EVP_PKEY* get_and_verify_pub_key_from_certificate_CLIENT_SIDE(X509* cert_server);
int serialize_PEM_Pub_Key(EVP_PKEY* pubkey, unsigned char** pub_key_buffer);
EVP_PKEY* deserialize_PEM_Pub_Key(int pubkey_size, unsigned char* pubkey_buf);
unsigned char* get_asymmetric_encrypted_digital_envelope(unsigned char* clear_buf, int clear_size, EVP_PKEY* pubkey, int* returning_size);
unsigned char* get_asymmetric_decrypted_digital_envelope(unsigned char* ciphertext_and_info_buf, int ciphertext_and_info_buf_size, EVP_PKEY* prvkey, int* returning_size);
bool server_authentication(EVP_PKEY** p_prvkey);
bool client_authentication(char* username_client, EVP_PKEY** p_prvkey);

// TO BE MOVED INTO crypto.h
void generate_symmetric_key(unsigned char** key, unsigned long key_len);

// TO BE MOVED INTO digital_signature.h
unsigned char* get_signature(unsigned char* clear_buf, int clear_size, EVP_PKEY* prvkey, int* returning_size);
bool verify_signature(unsigned char* clear_buf, int clear_size,unsigned char* sgnt_buf, int sgnt_size, EVP_PKEY* pubkey);