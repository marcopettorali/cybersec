#include "crypto.h"

#include <stdio.h>
#include <string.h>

#include "util.h"

#define TEST BIO_dump_fp(stdout, (const char *)aad, aad_len);

int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *ciphertext, unsigned char *tag) {
    // create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("EVP_CIPHER_CTX_new() failed\n");
        return -1;
    }

    // encrypt phase
    int len;
    int ciphertext_len;

    // encrypt init
    int ret = EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    if (ret != 1) {
        printf("EVP_EncryptInit() failed\n");
        return -1;
    }

    // feed the AAD
    ret = EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
    if (ret != 1) {
        printf("EVP_EncryptUpdate() failed (when adding aad)\n");
        return -1;
    }

    // feed plaintext
    ret = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if (ret != 1) {
        printf("EVP_EncryptUpdate() failed\n");
        return -1;
    }

    ciphertext_len = len;

    // finalize
    ret = EVP_EncryptFinal(ctx, ciphertext + len, &len);
    if (ret != 1) {
        printf("EVP_EncryptFinal() failed\n");
        return -1;
    }
    ciphertext_len += len;

    // get tag
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_SIZE, tag);
    if (ret != 1) {
        printf("EVP_CIPHER_CTX_ctrl() failed\n");
        return -1;
    }

    // free the context
    EVP_CIPHER_CTX_free(ctx);

    //TEST

    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len, unsigned char *tag, unsigned char *key,
                unsigned char *iv, int iv_len, unsigned char *plaintext) {
    int ret;

    // create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("EVP_CIPHER_CTX_new() failed\n");
        return -1;
    }

    // decrypt phase
    int len;
    int plaintext_len;

    // decrypt init
    ret = EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    if (ret != 1) {
        printf("EVP_DecryptInit() failed\n");
        return -1;
    }

    // feed the AAD
    ret = EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);
    if (ret != 1) {
        printf("EVP_DecryptUpdate() failed (when adding aad)\n");
        return -1;
    }
    // feed the ciphertext
    ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    if (ret != 1) {
        printf("EVP_DecryptUpdate() failed\n");
        return -1;
    }
    plaintext_len = len;

    // set tag
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_SIZE, tag);
    if (ret != 1) {
        printf("EVP_CIPHER_CTX_ctrl() failed\n");
        return -1;
    }

    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    // free the context
    EVP_CIPHER_CTX_cleanup(ctx);

    //TEST

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;

    } else {
        printf("Tag verify failed: ret = %d\n", ret);
        return -1;
    }
}

// DA MODIFICARE !!
unsigned char *prepare_gcm_ciphertext_new(char opcode, int *ciphertext_len, int counter, unsigned char *plaintext, int plaintext_len,
                                          unsigned char *shared_key) {
    unsigned char *ciphertext = (unsigned char *)malloc(GCM_IV_SIZE + GCM_TAG_SIZE + plaintext_len);
    *ciphertext_len = GCM_IV_SIZE + GCM_TAG_SIZE + plaintext_len;

    unsigned char *aad = (unsigned char *)malloc(GCM_AAD_SIZE);

    unsigned char *iv = (unsigned char *)malloc(GCM_IV_SIZE);
    unsigned char *tag = (unsigned char *)malloc(GCM_TAG_SIZE);

    RAND_poll();
    RAND_bytes(&iv[0], GCM_IV_SIZE);
    // prepare AAD (opcode,payload_len,IV,counter)
    int aad_index = 0;
    memcpy(&aad[aad_index], &opcode, OPCODE_SIZE);
    aad_index += OPCODE_SIZE;
    memcpy(&aad[aad_index], ciphertext_len, PAYLOAD_LEN_SIZE);
    aad_index += PAYLOAD_LEN_SIZE;
    memcpy(&aad[aad_index], iv, GCM_IV_SIZE);
    aad_index += GCM_IV_SIZE;
    memcpy(&aad[aad_index], &counter, COUNTER_SIZE);
    aad_index += COUNTER_SIZE;

    // initialize index in the ciphertext
    int ct_index = 0;

    if (gcm_encrypt(&plaintext[0], plaintext_len, &aad[0], GCM_AAD_SIZE, shared_key, &iv[0], GCM_IV_SIZE, &ciphertext[GCM_IV_SIZE + GCM_TAG_SIZE], &tag[0]) ==
        -1) {
        return NULL;
    }

    memcpy(&ciphertext[ct_index], iv, GCM_IV_SIZE);
    ct_index += GCM_IV_SIZE;

    memcpy(&ciphertext[ct_index], tag, GCM_TAG_SIZE);
    ct_index += GCM_TAG_SIZE;

    printf("PREPARE:\n");
    BIO_dump_fp(stdout, (const char *)&ciphertext[0], GCM_IV_SIZE + GCM_TAG_SIZE + plaintext_len);

    return ciphertext;
}

// DA MODIFICARE !!
unsigned char *extract_gcm_plaintext(char opcode, int counter, unsigned char *ciphertext, int ciphertext_len, unsigned char *shared_key,
                                     int *plaintext_len) {
    unsigned char *plaintext = (unsigned char *)malloc(ciphertext_len - (GCM_IV_SIZE + GCM_TAG_SIZE));
    *plaintext_len = ciphertext_len - (GCM_IV_SIZE + GCM_TAG_SIZE);

    unsigned char *aad = (unsigned char *)malloc(GCM_AAD_SIZE);

    unsigned char *iv = (unsigned char *)malloc(GCM_IV_SIZE);
    unsigned char *tag = (unsigned char *)malloc(GCM_TAG_SIZE);

    // initialize index in the ciphertext
    int ct_index = 0;

    memcpy(&iv[0], &ciphertext[ct_index], GCM_IV_SIZE);
    ct_index += GCM_IV_SIZE;

    memcpy(&tag[0], &ciphertext[ct_index], GCM_TAG_SIZE);
    ct_index += GCM_TAG_SIZE;

    // prepare AAD (opcode,payload_len,IV,counter)
    int aad_index = 0;
    memcpy(&aad[aad_index], &opcode, OPCODE_SIZE);
    aad_index += OPCODE_SIZE;
    memcpy(&aad[aad_index], &ciphertext_len, PAYLOAD_LEN_SIZE);
    aad_index += PAYLOAD_LEN_SIZE;
    memcpy(&aad[aad_index], iv, GCM_IV_SIZE);
    aad_index += GCM_IV_SIZE;
    memcpy(&aad[aad_index], &counter, COUNTER_SIZE);
    aad_index += COUNTER_SIZE;


    if (gcm_decrypt(&ciphertext[ct_index], ciphertext_len - (GCM_IV_SIZE + GCM_TAG_SIZE), &aad[0], GCM_AAD_SIZE, &tag[0], shared_key, &iv[0],
                    GCM_IV_SIZE, &plaintext[0]) == -1) {
        return NULL;
    }

    return plaintext;
}

EVP_PKEY *generate_dh_public_key(EVP_PKEY **my_dh_private_key, int control) {
    // load EC parameters
    EVP_PKEY_CTX *params_ctx;
    EVP_PKEY *params = NULL;
    params_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if (!(params_ctx)) {
        printf("Error in EVP_PKEY_CTX_new_id, in the function prepare_dh_public_key()\n");
        return NULL;
    };
    if (!EVP_PKEY_paramgen_init(params_ctx)) {
        printf("Error in EVP_PKEY_paramgen_init, in the function prepare_dh_public_key()\n");
        return NULL;
    }
    if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(params_ctx, NID_X9_62_prime256v1)) {
        printf("Error in EVP_PKEY_CTX_set_ec_paramgen_curve_nid, in the function prepare_dh_public_key()\n");
        return NULL;
    }
    if (!EVP_PKEY_paramgen(params_ctx, &params)) {
        printf("Error in EVP_PKEY_paramgen, in the function prepare_dh_public_key()\n");
        return NULL;
    }

    // create private key
    EVP_PKEY_CTX *ctx;
    if (NULL == (ctx = EVP_PKEY_CTX_new(params, NULL))) {
        printf("Error in EVP_PKEY_CTX_new, in the function prepare_dh_public_key()\n");
        return NULL;
    }
    if (!EVP_PKEY_keygen_init(ctx)) {
        printf("Error in EVP_PKEY_keygen_init, in the function prepare_dh_public_key()\n");
        return NULL;
    }
    if (!EVP_PKEY_keygen(ctx, &*(my_dh_private_key))) {
        printf("Error in EVP_PKEY_keygen, in the function prepare_dh_public_key()\n");
        return NULL;
    }

    // extract the public key
    char name[6] = "temp";
    if (control == 1) {
        strcat(name, "1");
    }
    FILE *temp = fopen(name, "w");
    if (!temp) {
        return NULL;
    }
    PEM_write_PUBKEY(temp, *(my_dh_private_key));
    fclose(temp);
    temp = fopen(name, "r");
    if (!temp) {
        return NULL;
    }
    EVP_PKEY *my_dh_public_key = PEM_read_PUBKEY(temp, NULL, NULL, NULL);
    fclose(temp);
    remove(name);

    // free all the structures
    EVP_PKEY_CTX_free(params_ctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);

    return my_dh_public_key;
}

unsigned char *derive_dh_public_key(EVP_PKEY *my_dh_private_key, EVP_PKEY *peer_dh_public_key, int *shared_key_length) {
    // choose the hash algorithm to use
    const EVP_MD *hash_algorithm = EVP_sha256();

    // derive the shared secret
    EVP_PKEY_CTX *derive_ctx;
    unsigned char *shared_secret;
    size_t shared_secret_len;

    derive_ctx = EVP_PKEY_CTX_new(my_dh_private_key, NULL);

    if (NULL == derive_ctx) {
        printf("Error in EVP_PKEY_CTX_new, in the function derive_dh_public_key()\n");
        return NULL;
    };
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
        printf("Error in EVP_PKEY_derive_init, in the function derive_dh_public_key()\n");
        return NULL;
    };
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_dh_public_key) <= 0) {
        printf("Error in EVP_PKEY_derive_set_peer, in the function derive_dh_public_key()\n");
        return NULL;
    };

    EVP_PKEY_derive(derive_ctx, NULL, &shared_secret_len);
    shared_secret = (unsigned char *)(malloc((int)(shared_secret_len)));
    if (!shared_secret) {
        printf("Error in malloc for the shared secret, in the function derive_dh_public_key()\n");
        return NULL;
    };
    if (EVP_PKEY_derive(derive_ctx, shared_secret, &shared_secret_len) <= 0) {
        printf("Error in EVP_PKEY_derive, in the function derive_dh_public_key()\n");
        return NULL;
    };

    // extract the digest of the shared secret
    unsigned char *shared_secret_digest;
    unsigned int shared_secret_digest_len;
    EVP_MD_CTX *hash_ctx;
    hash_ctx = EVP_MD_CTX_new();
    shared_secret_digest = (unsigned char *)malloc(EVP_MD_size(hash_algorithm));
    EVP_DigestInit(hash_ctx, hash_algorithm);
    EVP_DigestUpdate(hash_ctx, (unsigned char *)shared_secret, shared_secret_len);
    EVP_DigestFinal(hash_ctx, shared_secret_digest, &shared_secret_digest_len);

    // free all the structures
    EVP_PKEY_free(my_dh_private_key);
    EVP_PKEY_free(peer_dh_public_key);
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_MD_CTX_free(hash_ctx);

    *shared_key_length = shared_secret_digest_len;
    return shared_secret_digest;
}

/*int main() {
    int payload_len, plaintext_len;
    unsigned char *plaintext = (unsigned char *)malloc(10);
    memcpy(&plaintext[0], "BELLARAGA", 10);
    unsigned char *shared_key = (unsigned char *)malloc(128);
    memcpy(&shared_key[0],
           "SHAREDKEYSHAREDKEYSHAREDKEYSHAREDKEYSHAREDKEYSHAREDKEYSHAREDKEYSHAREDKEYSHAREDKEYSHAREDKEYSHAREDKEYSHAREDKEYSHAREDKEYSHAREDSHAR", 128);

    unsigned char *ciphertext = prepare_gcm_ciphertext_new(2, &payload_len, 1, &plaintext[0], 10, &shared_key[0]);
    unsigned char *received_pt = extract_gcm_plaintext(2, 1, &ciphertext[0], payload_len, &shared_key[0], &plaintext_len);

    printf("MESSAGE: %s\n", received_pt);

    return 0;
}*/

// DA TOGLIERE XK VECCHIE
unsigned char *prepare_gcm_ciphertext(unsigned char *plaintext, int plaintext_len, unsigned char *shared_key, int *ciphertext_len) {
    unsigned char *ciphertext = (unsigned char *)malloc(GCM_AAD_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE + plaintext_len);
    *ciphertext_len = GCM_AAD_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE + plaintext_len;

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

    return ciphertext;
}

unsigned char *extract_gcm_ciphertext(unsigned char *ciphertext, int ciphertext_len, unsigned char *shared_key, int *plaintext_len) {
    unsigned char *plaintext = (unsigned char *)malloc(ciphertext_len - (GCM_IV_SIZE + GCM_AAD_SIZE + GCM_TAG_SIZE));
    *plaintext_len = ciphertext_len - (GCM_IV_SIZE + GCM_AAD_SIZE + GCM_TAG_SIZE);

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

    return plaintext;
}