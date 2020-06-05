#include <openssl/evp.h>
#include <openssl/rand.h>

#define GCM_AAD_SIZE 16
#define GCM_IV_SIZE 16
#define GCM_KEY_SIZE 16
#define GCM_TAG_SIZE 16

// I'm not sure to leave it here
extern unsigned char* shared_key;

int gcm_encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* aad, int aad_len, unsigned char* key, unsigned char* iv, int iv_len,
                unsigned char* ciphertext, unsigned char* tag);

int gcm_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* aad, int aad_len, unsigned char* tag, unsigned char* key,
                unsigned char* iv, int iv_len, unsigned char* plaintext);

int prepare_gcm_ciphertext(unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext, unsigned char* shared_key);
int extract_gcm_ciphertext(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext, unsigned char* shared_key);