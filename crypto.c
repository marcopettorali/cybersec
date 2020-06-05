#include "crypto.h"

#include <stdio.h>
#include <string.h>

#include "util.h"

int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *ciphertext, unsigned char *tag) {
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

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len, unsigned char *tag, unsigned char *key,
                unsigned char *iv, int iv_len, unsigned char *plaintext) {
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

int prepare_gcm_ciphertext(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, unsigned char* shared_key) {
    unsigned char *iv = (unsigned char *)malloc(GCM_IV_SIZE);
    unsigned char *aad = (unsigned char *)malloc(GCM_AAD_SIZE);
    unsigned char *tag = (unsigned char *)malloc(GCM_TAG_SIZE);

    RAND_poll();
    RAND_bytes(&iv[0], GCM_IV_SIZE);
    RAND_bytes(&aad[0], GCM_AAD_SIZE);

    // initialize index in the ciphertext
    int ct_index = 0;

    gcm_encrypt(&plaintext[0], plaintext_len, aad, GCM_AAD_SIZE, shared_key, iv, GCM_IV_SIZE, &ciphertext[GCM_IV_SIZE + GCM_AAD_SIZE + GCM_TAG_SIZE],
                tag);

    memcpy(&ciphertext[ct_index], iv, GCM_IV_SIZE);
    ct_index += GCM_IV_SIZE;

    memcpy(&ciphertext[ct_index], aad, GCM_AAD_SIZE);
    ct_index += GCM_AAD_SIZE;

    memcpy(&ciphertext[ct_index], tag, GCM_TAG_SIZE);
    ct_index += GCM_TAG_SIZE;
}

int extract_gcm_ciphertext(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, unsigned char* shared_key) {
    unsigned char *iv = (unsigned char *)malloc(GCM_IV_SIZE);
    unsigned char *aad = (unsigned char *)malloc(GCM_AAD_SIZE);
    unsigned char *tag = (unsigned char *)malloc(GCM_TAG_SIZE);

    // initialize index in the ciphertext
    int ct_index = 0;

    memcpy(&iv[0], &ciphertext[ct_index], GCM_IV_SIZE);
    ct_index += GCM_IV_SIZE;

    memcpy(&aad[0], &ciphertext[ct_index], GCM_AAD_SIZE);
    ct_index += GCM_AAD_SIZE;

    memcpy(&tag[0], &ciphertext[ct_index], GCM_TAG_SIZE);
    ct_index += GCM_TAG_SIZE;

    gcm_decrypt(&ciphertext[ct_index], ciphertext_len - (GCM_IV_SIZE + GCM_AAD_SIZE + GCM_TAG_SIZE), &aad[0], GCM_AAD_SIZE, &tag[0], shared_key,
                &iv[0], GCM_IV_SIZE, &plaintext[0]);
}

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
}