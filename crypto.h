#include <openssl/evp.h>
#include <openssl/rand.h>

#define GCM_AAD_SIZE 16
#define GCM_IV_SIZE 16
#define GCM_KEY_SIZE 16
#define GCM_TAG_SIZE 16

int gcm_encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* aad, int aad_len, unsigned char* key, unsigned char* iv, int iv_len, unsigned char* ciphertext, unsigned char* tag);

int gcm_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* aad, int aad_len, unsigned char* tag, unsigned char* key, unsigned char* iv, int iv_len, unsigned char* plaintext);

unsigned char* prepare_gcm_ciphertext(unsigned char* plaintext, int plaintext_len, unsigned char* shared_key, int* ciphertext_len);
unsigned char* extract_gcm_ciphertext(unsigned char* ciphertext, int ciphertext_len, unsigned char* shared_key, int* plaintext_len);

// void generate_symmetric_key(unsigned char **key,unsigned long key_len); TO BE MOVED HERE