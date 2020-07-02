#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define GCM_AAD_SIZE OPCODE_SIZE + PAYLOAD_LEN_SIZE + GCM_IV_SIZE + COUNTER_SIZE
#define GCM_IV_SIZE 16
#define GCM_KEY_SIZE 16
#define GCM_TAG_SIZE 16

int gcm_encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* aad, int aad_len, unsigned char* key, unsigned char* iv, int iv_len,
                unsigned char* ciphertext, unsigned char* tag);

int gcm_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* aad, int aad_len, unsigned char* tag, unsigned char* key,
                unsigned char* iv, int iv_len, unsigned char* plaintext);

unsigned char* prepare_gcm_ciphertext(char opcode, int *payload_len ,int counter, unsigned char *plaintext, int plaintext_len, unsigned char *shared_key);
unsigned char* extract_gcm_plaintext(char opcode, int counter, unsigned char* payload, int payload_len, unsigned char* shared_key, int* plaintext_len);

EVP_PKEY *generate_dh_public_key(EVP_PKEY *my_dh_private_key, int control);
unsigned char *derive_dh_public_key(EVP_PKEY *my_dh_private_key, EVP_PKEY *peer_dh_public_key, int *shared_key_length);