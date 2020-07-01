#include "crypto.h"

#include <stdio.h>
#include <string.h>

#include "util.h"

int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext, unsigned char *tag) {
    // create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        EXCEPTION("EVP_CIPHER_CTX_new() failed", __func__);
    }

    // encrypt phase
    int len;
    int ciphertext_len;

    // encrypt init
    int ret = EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    if (ret != 1) {
        EXCEPTION("EVP_EncryptInit() failed", __func__);
    }

    // feed the AAD
    ret = EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
    if (ret != 1) {
        EXCEPTION("EVP_EncryptUpdate() failed (when adding aad)", __func__);
    }

    // feed plaintext
    ret = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if (ret != 1) {
        EXCEPTION("EVP_EncryptUpdate() failed", __func__);
    }
    ciphertext_len = len;

    // finalize
    ret = EVP_EncryptFinal(ctx, ciphertext + len, &len);
    if (ret != 1) {
        EXCEPTION("EVP_EncryptFinal() failed", __func__);
    }
    ciphertext_len += len;

    // get tag
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_SIZE, tag);
    if (ret != 1) {
        EXCEPTION("EVP_CIPHER_CTX_ctrl() failed", __func__);
    }

    // free the context
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *plaintext) {
    int ret;

    // create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        EXCEPTION("EVP_CIPHER_CTX_new() failed", __func__);
    }

    // decrypt phase
    int len;
    int plaintext_len;

    // decrypt init
    ret = EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    if (ret != 1) {
        EXCEPTION("EVP_DecryptInit() failed", __func__);
    }

    // feed the AAD
    ret = EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);
    if (ret != 1) {
        EXCEPTION("EVP_DecryptUpdate() failed (when adding aad)", __func__);
    }

    // feed the ciphertext
    ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    if (ret != 1) {
        EXCEPTION("EVP_DecryptUpdate() failed", __func__);
    }
    plaintext_len = len;

    // set tag
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_SIZE, tag);
    if (ret != 1) {
        EXCEPTION("EVP_CIPHER_CTX_ctrl() failed", __func__);
    }

    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    // free the context
    EVP_CIPHER_CTX_cleanup(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;

    } else {
        DEBUG("Tag verify failed", __func__);
        return -1;
    }
}


unsigned char *prepare_gcm_ciphertext(char opcode, int *payload_len ,int counter, unsigned char *plaintext, int plaintext_len, unsigned char *shared_key) {
    // buffer to return  IV || TAG || Ciphertext
    unsigned char *ciphertext = (unsigned char *)malloc(plaintext_len);
    *payload_len = GCM_IV_SIZE + GCM_TAG_SIZE + plaintext_len;
    unsigned char * buffer_to_return = (unsigned char *)malloc(*payload_len);

    unsigned char *iv = (unsigned char *)malloc(GCM_IV_SIZE);
    unsigned char *aad = (unsigned char *)malloc(OPCODE_SIZE + PAYLOAD_LEN_SIZE + GCM_IV_SIZE + COUNTER_SIZE);
    unsigned char *tag = (unsigned char *)malloc(GCM_TAG_SIZE);

    RAND_poll();
    RAND_bytes(&iv[0], GCM_IV_SIZE);
    //prepare AAD (opcode,payload_len,IV,counter)
    int aad_index = 0;
    memcpy(&aad[aad_index], &opcode, OPCODE_SIZE);
    aad_index += OPCODE_SIZE;
    memcpy(&aad[aad_index], payload_len, PAYLOAD_LEN_SIZE);
    aad_index += PAYLOAD_LEN_SIZE;
    memcpy(&aad[aad_index], iv, GCM_IV_SIZE);
    aad_index += GCM_IV_SIZE;
    memcpy(&aad[aad_index], &counter, COUNTER_SIZE);
    aad_index += COUNTER_SIZE;

    // initialize index in the ciphertext
    int buffer_to_return_index = 0;

    //DA MODIFICARE (deve prendere in ingresso AAD e plaintext)
    gcm_encrypt(&plaintext[0], plaintext_len, aad, GCM_AAD_SIZE, shared_key, iv, GCM_IV_SIZE, &ciphertext[GCM_IV_SIZE + GCM_AAD_SIZE + GCM_TAG_SIZE], tag);

    // buffer to return IV || TAG || Ciphertext

    memcpy(&buffer_to_return[buffer_to_return_index], iv, GCM_IV_SIZE);
    buffer_to_return_index += GCM_IV_SIZE;

    memcpy(&buffer_to_return[buffer_to_return_index], tag, GCM_TAG_SIZE);
    buffer_to_return_index += GCM_TAG_SIZE;

    memcpy(&buffer_to_return[buffer_to_return_index], ciphertext, plaintext_len);
    buffer_to_return_index += plaintext_len;

    free(ciphertext);

    return buffer_to_return;
}

//DA MODIFICARE !!
unsigned char *extract_gcm_plaintext(char opcode, int counter, unsigned char *payload, int payload_len, unsigned char *shared_key, int *plaintext_len) {
    // PAYLOAD =  IV || TAG || ciphertext
    // Buffer to return
    unsigned char *plaintext = (unsigned char *)malloc(payload_len - (GCM_IV_SIZE + GCM_TAG_SIZE));
    *plaintext_len = payload_len - (GCM_IV_SIZE + GCM_TAG_SIZE);

    unsigned char *iv = (unsigned char *)malloc(GCM_IV_SIZE);
    unsigned char *tag = (unsigned char *)malloc(GCM_TAG_SIZE);
    unsigned char *ciphertext = (unsigned char *)malloc(payload_len - (GCM_IV_SIZE + GCM_TAG_SIZE));

    // initialize index in the payload_index
    int payload_index = 0;

    memcpy(&iv[0], &payload[payload_index], GCM_IV_SIZE);
    payload_index += GCM_IV_SIZE;

    memcpy(&tag[0], &payload[payload_index], GCM_TAG_SIZE);
    payload_index += GCM_TAG_SIZE;

    memcpy(&ciphertext[0], &payload[payload_index], payload_len - (GCM_IV_SIZE + GCM_TAG_SIZE));
    payload_index += payload_len - (GCM_IV_SIZE + GCM_TAG_SIZE);

    //prepare AAD (opcode,payload_len,IV,counter)
    unsigned char *aad = (unsigned char *)malloc(GCM_AAD_SIZE);
    int aad_index = 0;
    memcpy(&aad[aad_index], &opcode, OPCODE_SIZE);
    aad_index += OPCODE_SIZE;
    memcpy(&aad[aad_index], &payload_len, PAYLOAD_LEN_SIZE);
    aad_index += PAYLOAD_LEN_SIZE;
    memcpy(&aad[aad_index], iv, GCM_IV_SIZE);
    aad_index += GCM_IV_SIZE;
    memcpy(&aad[aad_index], &counter, COUNTER_SIZE);
    aad_index += COUNTER_SIZE;

    gcm_decrypt(ciphertext, payload_len - (GCM_IV_SIZE + GCM_TAG_SIZE), &aad[0], GCM_AAD_SIZE, &tag[0], shared_key, &iv[0], GCM_IV_SIZE, &plaintext[0]);

    return plaintext;
}
/* TO BE MOVED HERE
void generate_symmetric_key(unsigned char **key,unsigned long key_len){
        RAND_poll();
        int rc = RAND_bytes(*key, key_len);
        //unsigned long err = ERR_get_error();

        if(rc != 1) {
                printf("Error in generating key\n");
                exit(1);
        }
}*/
/*
int main() {
    int tag_len;

    unsigned char *pt = "BELLARAGA!!!!";
    unsigned char* shared_key = (unsigned char*)malloc(18);
    memcpy(&shared_key[0], "abcdefghilmnopqrs", 18);

    unsigned char *ciphertext = (unsigned char *)malloc(GCM_AAD_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE + strlen(pt));
    prepare_gcm_ciphertext(&pt[0], strlen(pt), &ciphertext[0], &shared_key[0]);

    unsigned char *received_pt = (unsigned char *)malloc(GCM_AAD_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE + strlen(pt));
    extract_gcm_ciphertext(&ciphertext[0], GCM_AAD_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE + strlen(pt), &received_pt[0], &shared_key[0]);

    printf("plaintext = %s.\n", received_pt);
    return 0;
}*/