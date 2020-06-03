#include "crypto.h"

#include <stdio.h>
#include <string.h>

#include "util.h"

#define GCM_TAG_SIZE 16

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

int main() {
    int tag_len;

    unsigned char *pt = "shiss";
    unsigned char *key = "abcdefghilmnopqrs";
    unsigned char *iv = "abcdefghilm";
    unsigned char *aad = "pqrstuvwxyz";
    unsigned char *ct = (unsigned char *)malloc(strlen(pt));
    unsigned char *tag = (unsigned char *)malloc(GCM_TAG_SIZE);

    gcm_encrypt(pt, strlen(pt), aad, strlen(iv), key, iv, strlen(iv), ct, tag);

    unsigned char *buf = (unsigned char *)malloc(strlen(pt));
    gcm_decrypt(ct, strlen(pt), aad, strlen(aad), tag, key, iv, strlen(iv), buf);

    printf("plaintext = %s.\n", buf);
    return 0;
}