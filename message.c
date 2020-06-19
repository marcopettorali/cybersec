#include <stdio.h>
#include<stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h> // for INT_MAX
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "util.h"
#include "message.h"
#include "pub_key_crypto.h"
#include "crypto.h"
#include "list.h"
#include "net.h"

void generate_nonce(unsigned char **nonce,unsigned long nonce_len){
	RAND_poll();
	int rc = RAND_bytes(*nonce, nonce_len);
	//unsigned long err = ERR_get_error();

	if(rc != 1) {
		printf("Error in generating nonce\n");
		exit(1);
	}
}

void free_MESSAGE(Message** mex){
    free((*(mex))->payload);
    *mex = NULL;
}

void reformat_nickname(char* nick){
    nick[strlen(nick)-1]='\0';
}

Message* create_M1_CLIENT_SERVER_AUTH(char* username_client, AuthenticationInstance * authInstance){
    unsigned char *nonce = (unsigned char *)malloc(NONCE_32);
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
    
    mex->opcode = (char)M1_CLIENT_SERVER_AUTH; 

    mex->payload = (unsigned char *)malloc(NICKNAME_LENGTH + sizeof(NICKNAME_SERVER) + NONCE_32);
    
    //Start creating payload |ID_CLIENT ID_server NONCE|
    memcpy(&(mex->payload[byte_index]),&username_client[0], NICKNAME_LENGTH);
    byte_index += NICKNAME_LENGTH;

    memcpy(&(mex->payload[byte_index]),NICKNAME_SERVER, sizeof(NICKNAME_SERVER));
    byte_index += sizeof(NICKNAME_SERVER);
    
    generate_nonce(&nonce,NONCE_32);

    memcpy(&(mex->payload[byte_index]), &nonce[0], NONCE_32);
    byte_index += NONCE_32;

    mex->payload_len = byte_index;
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);


    //Initialize values in authInstance
    memcpy(authInstance->nickname_client,&username_client[0], NICKNAME_LENGTH);
    memcpy(authInstance->nickname_server,NICKNAME_SERVER, sizeof(NICKNAME_SERVER));
    memcpy(authInstance->nonce_client, &nonce[0], NONCE_32);

    free(nonce);

    return mex;
}

int handler_M1_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance){
    //Format mex |1|len|ID_CLIENT ID_server NONCE|
    
    // initialize index in the payload
    int pd_index = 0;

    memcpy(authInstance->nickname_client, &payload[pd_index], NICKNAME_LENGTH);
    pd_index += NICKNAME_LENGTH;

    memcpy(authInstance->nickname_server, &payload[pd_index], sizeof(NICKNAME_SERVER));
    pd_index += sizeof(NICKNAME_SERVER);

    memcpy(authInstance->nonce_client, &payload[pd_index], payload_len - (unsigned int)pd_index);
    pd_index += payload_len - (unsigned int)pd_index;

    printf("[Unknown client handler]: Request of authentication from client: %s\n",authInstance->nickname_client);
    printf("[Unknown client handler]: To %s\n",authInstance->nickname_server);

    if(strncmp(authInstance->nickname_server,NICKNAME_SERVER,sizeof(NICKNAME_SERVER))!=0){
        printf("[Unknown client handler]: wrong destinator: abort\n");
        return 0;
    }

    return 1;
}


Message* create_M2_CLIENT_SERVER_AUTH(AuthenticationInstance * authInstance){
    //Mex format |op|len|Cs_len Cs EpubKa(ID_SERVER ID_CLIENT NONCEa CHallengeA) 
    
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = (char)M2_CLIENT_SERVER_AUTH; 

    //get server's certificate Cs
    FILE* server_cert_file = fopen("./server_certificates/server_cert.pem", "r");
    if(!server_cert_file){ printf("Error: Server Certificate NOT FOUND!\n"); return NULL;}
    X509* server_cert = PEM_read_X509(server_cert_file, NULL, NULL, NULL);
    fclose(server_cert_file);
    if(!server_cert){ printf("Error: PEM_read_X509 returned NULL\n"); return NULL; }

	//serialize server's certificate Cs
    unsigned char* cert_buf = NULL;
    int cert_size = i2d_X509(server_cert,&cert_buf);
    if(cert_size < 0){printf("Error: Server Certificate SERIALIZATION failed!\n"); return NULL;}

    //retrieving PubKeyClient
    EVP_PKEY* pub_key_client = get_and_verify_pub_key_from_certificate(authInstance->nickname_client);
    if(pub_key_client == NULL){ printf("Error: Unable to retrieve PubKeyClient\n"); return NULL; }

    //generate challenge for client CHa
    unsigned char *challenge = (unsigned char *)malloc(CHALLENGE_32);
    generate_nonce(&challenge,CHALLENGE_32);
    memcpy(authInstance->challenge_to_client, challenge, CHALLENGE_32);
    free(challenge);

    //Start creating plaintext |ID_SERVER ID_CLIENT NONCEa CHallengeA|
    unsigned char* plaintext_buffer = (unsigned char *)malloc(sizeof(NICKNAME_SERVER) + NICKNAME_LENGTH + NONCE_32 +CHALLENGE_32);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]),NICKNAME_SERVER, sizeof(NICKNAME_SERVER));
    pt_byte_index += sizeof(NICKNAME_SERVER);

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nickname_client, NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nonce_client, NONCE_32);
    pt_byte_index += NONCE_32;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->challenge_to_client, CHALLENGE_32);
    pt_byte_index += CHALLENGE_32;

    //get ciphertext EpubKeyClient
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = get_asymmetric_encrypted_digital_envelope(plaintext_buffer, pt_byte_index, pub_key_client,&ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext EpubKeyClient\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
    
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(sizeof(int) + cert_size + ciphertext_and_info_buf_size); //POSTPONED AFTER EpubKa(..)

    //Start creating payload |Cs_len Cs
    memcpy(&(mex->payload[byte_index]),&cert_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(mex->payload[byte_index]),&cert_buf[0], cert_size);
    byte_index += cert_size;
    
    OPENSSL_free(cert_buf);

    //Continue creating payload |.. EpubKa(ID_SERVER ID_CLIENT NONCEa CHallengeA)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;

    //FREE STUFF!!!
    X509_free(server_cert);
    EVP_PKEY_free(pub_key_client);
    free(ciphertext_and_info_buf);

    //update values in authInstance
    authInstance->expected_opcode = (char)M3_CLIENT_SERVER_AUTH;

    return mex;
}

int handler_M2_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,EVP_PKEY* privkey){
    //Format mex |1|len|Cs_len Cs EpubKa(ID_SERVER ID_CLIENT NONCEa CHallengeA)
    
    // initialize index in the payload
    int pd_index = 0;

    //retriving payload |Cs_len
    int cert_size;
    memcpy(&cert_size,&(payload[pd_index]),sizeof(int));
    pd_index += sizeof(int);

    //retriving payload |.. Cs
    unsigned char* cert_buf = (unsigned char*)malloc(cert_size);
    memcpy(&cert_buf[0],&(payload[pd_index]), cert_size);
    pd_index += cert_size;
    //deserialize server's certificate Cs
    X509* cert_server = d2i_X509(NULL,(const unsigned char**)&cert_buf,cert_size);
    if(!cert_server){printf("Error: Server Certificate DESERIALIZATION failed!\n"); return 0;}

    //retrieving PubKeyServer
    EVP_PKEY* pub_key_server = get_and_verify_pub_key_from_certificate_CLIENT_SIDE(cert_server);
    if(pub_key_server == NULL){ printf("Error: Unable to retrieve PubKeyServer\n"); return 0; }
    

    //Needed to create M3
    authInstance->server_pub_key = pub_key_server;
    //get plaintext
    unsigned char* ciphertext = &(payload[pd_index]);
    int ciphertext_size = payload_len - pd_index;
    int plaintext_size;
    unsigned char* plaintext = get_asymmetric_decrypted_digital_envelope(ciphertext,ciphertext_size,privkey,&plaintext_size);
    if(plaintext == NULL){printf("Error in decryption digital envelope\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M2_CLIENT_SERVER_AUTH(plaintext,authInstance) == false){
        printf("Not consistent info received in M2 auth protocol\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M2_CLIENT_SERVER_AUTH(unsigned char * plaintext,AuthenticationInstance* authInstance){
    
    //declare buffer
    unsigned char* server_nickname_rec = (unsigned char*)malloc(sizeof(NICKNAME_SERVER));
    unsigned char* client_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    unsigned char* nonce_client_rec = (unsigned char*)malloc(NONCE_32);
    unsigned char* challenge_to_client_rec = (unsigned char*)malloc(CHALLENGE_32);

    int pt_byte_index = 0;

    memcpy(server_nickname_rec, &(plaintext[pt_byte_index]), sizeof(NICKNAME_SERVER));
    pt_byte_index+= sizeof(NICKNAME_SERVER);

    memcpy(client_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(nonce_client_rec,&(plaintext[pt_byte_index]), NONCE_32);
    pt_byte_index += NONCE_32;

    memcpy(challenge_to_client_rec, &(plaintext[pt_byte_index]) ,CHALLENGE_32);
    pt_byte_index += CHALLENGE_32;

    if(strncmp(authInstance->nickname_server,(char *)server_nickname_rec,sizeof(NICKNAME_SERVER))!=0){printf("Mismatch server nickname in M2\n");return false;}
    if(strncmp(authInstance->nickname_client,(char *)client_nickname_rec,NICKNAME_LENGTH)!=0){printf("Mismatch client nickname in M2\n");return false;}
    if(memcmp(authInstance->nonce_client,nonce_client_rec,NONCE_32)!=0){printf("Mismatch nonce in M2\n");return false;}

    memcpy(authInstance->challenge_to_client, challenge_to_client_rec,CHALLENGE_32);

    free(server_nickname_rec);
    free(client_nickname_rec);
    free(nonce_client_rec);
    free(challenge_to_client_rec);

    return true;
}


Message* create_M3_CLIENT_SERVER_AUTH(AuthenticationInstance * authInstance){
    //Mex format |op|len|EpubKServer(ID_CLIENT ID_SERVER CHallengeA CHallengeS Kas) 

  
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = (char)M3_CLIENT_SERVER_AUTH; 


    //generate challenge for server CHs
    unsigned char *challenge = (unsigned char *)malloc(CHALLENGE_32);
    generate_nonce(&challenge,CHALLENGE_32);
    memcpy(authInstance->challenge_to_server, challenge, CHALLENGE_32);
    free(challenge);

    //generate symmetric key Kas
    unsigned char *symmetric_key = (unsigned char *)malloc(GCM_KEY_SIZE);
    generate_symmetric_key(&symmetric_key,GCM_KEY_SIZE); //on 128 bit
    memcpy(authInstance->symmetric_key, symmetric_key, GCM_KEY_SIZE);
    memset(symmetric_key, 0, GCM_KEY_SIZE);
    free(symmetric_key);


    //Start creating plaintext |ID_CLIENT ID_SERVER CHallengeA CHallengeS Kas|
    unsigned char* plaintext_buffer = (unsigned char *)malloc(NICKNAME_LENGTH + sizeof(NICKNAME_SERVER) + 2 * CHALLENGE_32 + GCM_KEY_SIZE);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nickname_client, NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(&(plaintext_buffer[pt_byte_index]),NICKNAME_SERVER, sizeof(NICKNAME_SERVER));
    pt_byte_index += sizeof(NICKNAME_SERVER);

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->challenge_to_client, CHALLENGE_32);
    pt_byte_index += CHALLENGE_32;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->challenge_to_server, CHALLENGE_32);
    pt_byte_index += CHALLENGE_32;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->symmetric_key, GCM_KEY_SIZE);
    pt_byte_index += GCM_KEY_SIZE;

    //get ciphertext EpubKeyServer
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = get_asymmetric_encrypted_digital_envelope(plaintext_buffer, pt_byte_index, authInstance->server_pub_key,&ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext EpubKeyServer\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
    
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);


    //Start creating payload |EpubKServer(ID_CLIENT ID_SERVER CHallengeA CHallengeS Kas)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);

    //update values in authInstance
    authInstance->expected_opcode = (char)M4_CLIENT_SERVER_AUTH;

    return mex;
}

int handler_M3_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,EVP_PKEY* privkey){
    //Format mex |3|len|EpubKServer(ID_CLIENT ID_SERVER CHallengeA CHallengeS Kas)

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    unsigned char* plaintext = get_asymmetric_decrypted_digital_envelope(ciphertext,ciphertext_size,privkey,&plaintext_size);
    if(plaintext == NULL){printf("Error in decryption digital envelope\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M3_CLIENT_SERVER_AUTH(plaintext,authInstance) == false){
        printf("Not consistent info received in M3 auth protocol\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M3_CLIENT_SERVER_AUTH(unsigned char * plaintext,AuthenticationInstance* authInstance){
    //Call on server side

    //declare buffer
    unsigned char* client_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    unsigned char* server_nickname_rec = (unsigned char*)malloc(sizeof(NICKNAME_SERVER));
    unsigned char* challenge_to_client_rec = (unsigned char*)malloc(CHALLENGE_32);
    unsigned char* challenge_to_server_rec = (unsigned char*)malloc(CHALLENGE_32);
    unsigned char* symmetric_key_rec = (unsigned char*)malloc(GCM_KEY_SIZE);

    int pt_byte_index = 0;

    memcpy(client_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(server_nickname_rec, &(plaintext[pt_byte_index]), sizeof(NICKNAME_SERVER));
    pt_byte_index+= sizeof(NICKNAME_SERVER);

    memcpy(challenge_to_client_rec, &(plaintext[pt_byte_index]) ,CHALLENGE_32);
    pt_byte_index += CHALLENGE_32;

    memcpy(challenge_to_server_rec, &(plaintext[pt_byte_index]) ,CHALLENGE_32);
    pt_byte_index += CHALLENGE_32;

    memcpy(symmetric_key_rec, &(plaintext[pt_byte_index]) ,GCM_KEY_SIZE);
    pt_byte_index += GCM_KEY_SIZE;

    if(strncmp(authInstance->nickname_client,(char *)client_nickname_rec,NICKNAME_LENGTH)!=0){printf("Mismatch client nickname in M3\n");return false;}
    if(strncmp(authInstance->nickname_server,(char *)server_nickname_rec,sizeof(NICKNAME_SERVER))!=0){printf("Mismatch server nickname in M3\n");return false;}
    if(memcmp(authInstance->challenge_to_client,challenge_to_client_rec,CHALLENGE_32)!=0){printf("Mismatch challenge_to_client in M3\n");return false;}

    memcpy(authInstance->challenge_to_server, challenge_to_server_rec,CHALLENGE_32);
    memcpy(authInstance->symmetric_key, symmetric_key_rec,GCM_KEY_SIZE);

    free(client_nickname_rec);
    free(server_nickname_rec);
    free(challenge_to_client_rec);
    free(challenge_to_server_rec);
    free(symmetric_key_rec);

    return true;
}


Message* create_M4_CLIENT_SERVER_AUTH(AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(ID_SERVER ID_CLIENT CHallengeS) 

    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = (char)M4_CLIENT_SERVER_AUTH; 



    //Start creating plaintext |EKas(ID_SERVER ID_CLIENT CHallengeS)|
    unsigned char* plaintext_buffer = (unsigned char *)malloc(sizeof(NICKNAME_SERVER) + NICKNAME_LENGTH + CHALLENGE_32);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]),NICKNAME_SERVER, sizeof(NICKNAME_SERVER));
    pt_byte_index += sizeof(NICKNAME_SERVER);

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nickname_client, NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->challenge_to_server, CHALLENGE_32);
    pt_byte_index += CHALLENGE_32;


    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
    
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);


    //Start creating payload |EKas(ID_SERVER ID_CLIENT CHallengeS)
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);

    //update values in authInstance
    authInstance->expected_opcode = (char)SUCCESSFUL_CLIENT_SERVER_AUTH; //EXPECTED OPCODE > SUCCESSFUL_CLIENT_SERVER_AUTH

    return mex;
}

int handler_M4_CLIENT_SERVER_AUTH(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance){
    //Format mex |4|len|EKas(ID_SERVER ID_CLIENT CHallengeS)

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M4_CLIENT_SERVER_AUTH(plaintext,authInstance) == false){
        printf("Not consistent info received in M4 auth protocol\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M4_CLIENT_SERVER_AUTH(unsigned char * plaintext,AuthenticationInstance* authInstance){
    //Call on client side

    //declare buffer
    unsigned char* server_nickname_rec = (unsigned char*)malloc(sizeof(NICKNAME_SERVER));
    unsigned char* client_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    unsigned char* challenge_to_server_rec = (unsigned char*)malloc(CHALLENGE_32);

    int pt_byte_index = 0;

    memcpy(server_nickname_rec, &(plaintext[pt_byte_index]), sizeof(NICKNAME_SERVER));
    pt_byte_index+= sizeof(NICKNAME_SERVER);
    
    memcpy(client_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(challenge_to_server_rec, &(plaintext[pt_byte_index]) ,CHALLENGE_32);
    pt_byte_index += CHALLENGE_32;

    if(strncmp(authInstance->nickname_server,(char *)server_nickname_rec,sizeof(NICKNAME_SERVER))!=0){printf("Mismatch server nickname in M4\n");return false;}
    if(strncmp(authInstance->nickname_client,(char *)client_nickname_rec,NICKNAME_LENGTH)!=0){printf("Mismatch client nickname in M4\n");return false;}
    if(memcmp(authInstance->challenge_to_server,challenge_to_server_rec,CHALLENGE_32)!=0){printf("Mismatch challenge_to_server in M4\n");return false;}

    free(server_nickname_rec);
    free(client_nickname_rec);
    free(challenge_to_server_rec);

    return true;
}

Message* create_M_REQ_LIST(AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(NONCE_CLIENT)| //otherwise replay attack
    unsigned char* nonce = (unsigned char*)malloc(NONCE_32);
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = M_REQ_LIST;

    //Start creating plaintext |NONCE_CLIENT|
    //unsigned char* plaintext_buffer = (unsigned char *)malloc(NICKNAME_LENGTH + sizeof(NICKNAME_SERVER) + NONCE_32);
    unsigned char* plaintext_buffer = (unsigned char *)malloc(NONCE_32);
    int pt_byte_index = 0;

    generate_nonce(&nonce,NONCE_32);

    memcpy(&(plaintext_buffer[pt_byte_index]), &nonce[0], NONCE_32);
    pt_byte_index += NONCE_32;

    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas in M_REQ_LIST\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
    
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);

    //Start creating payload |EKas(ID_CLIENT ID_SERVER NONCE_CLIENT)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);

    //update values in authInstance
    memcpy(authInstance->nonce_client, &nonce[0], NONCE_32);

    free(nonce);

    return mex;
}

int handler_M_REQ_LIST(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance){
    //Format mex |op|len|EKas(NONCE_CLIENT)

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_REQ_LISt\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_REQ_LIST(plaintext,authInstance) == false){
        printf("Not consistent info received in M_REQ_LIST\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M_REQ_LIST(unsigned char * plaintext,AuthenticationInstance* authInstance){
    //Call on server side

    //declare buffer (NONCE_CLIENT)
    //unsigned char* client_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    //unsigned char* server_nickname_rec = (unsigned char*)malloc(sizeof(NICKNAME_SERVER));
    unsigned char* nonce_client_rec = (unsigned char*)malloc(NONCE_32);

    int pt_byte_index = 0;

    /*memcpy(client_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(server_nickname_rec, &(plaintext[pt_byte_index]), sizeof(NICKNAME_SERVER));
    pt_byte_index+= sizeof(NICKNAME_SERVER);*/

    memcpy(nonce_client_rec, &(plaintext[pt_byte_index]) ,NONCE_32);
    pt_byte_index += NONCE_32;

    //if(strncmp(authInstance->nickname_client,(char *)client_nickname_rec,NICKNAME_LENGTH)!=0){printf("Mismatch client nickname in M_REQ_LIST\n");return false;}
    //if(strncmp(authInstance->nickname_server,(char *)server_nickname_rec,sizeof(NICKNAME_SERVER))!=0){printf("Mismatch server nickname in M_REQ_LIST\n");return false;}
    if(authInstance->expected_opcode < SUCCESSFUL_CLIENT_SERVER_AUTH){printf("Received M_REQ_LIST but not yet authenticated client\n");return false;}

    memcpy(authInstance->nonce_client, nonce_client_rec, NONCE_32);

    free(nonce_client_rec);
    return true;
}

Message* create_M_LISTEN_PORT_CLIENT_P2P(int port,AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(ID_CLIENT ID_SERVER PORT)|
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = M_LISTEN_PORT_CLIENT_P2P;

    //Start creating plaintext |ID_CLIENT ID_SERVER PORT|
    unsigned char* plaintext_buffer = (unsigned char *)malloc(NICKNAME_LENGTH + sizeof(NICKNAME_SERVER) + sizeof(int));
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nickname_client, NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(&(plaintext_buffer[pt_byte_index]),NICKNAME_SERVER, sizeof(NICKNAME_SERVER));
    pt_byte_index += sizeof(NICKNAME_SERVER);

    memcpy(&(plaintext_buffer[pt_byte_index]), &port, sizeof(int));
    pt_byte_index += sizeof(int);

    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas in M_LISTEN_PORT_CLIENT_P2P\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
    
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);

    //Start creating payload |EKas(ID_CLIENT ID_SERVER PORT)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);

    return mex;
}

int handler_M_LISTEN_PORT_CLIENT_P2P(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,int* port){
    //Format mex |op|len|EKas(ID_CLIENT ID_SERVER PORT)

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_LISTEN_PORT_CLIENT_P2P\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_LISTEN_PORT_CLIENT_P2P(plaintext,authInstance,port) == false){
        printf("Not consistent info received in M_LISTEN_PORT_CLIENT_P2P\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M_LISTEN_PORT_CLIENT_P2P(unsigned char * plaintext,AuthenticationInstance* authInstance, int* port){
    //Call on server side

    //declare buffer (ID_CLIENT ID_SERVER PORT)
    unsigned char* client_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    unsigned char* server_nickname_rec = (unsigned char*)malloc(sizeof(NICKNAME_SERVER));
    int port_rec;

    int pt_byte_index = 0;

    memcpy(client_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(server_nickname_rec, &(plaintext[pt_byte_index]), sizeof(NICKNAME_SERVER));
    pt_byte_index+= sizeof(NICKNAME_SERVER);

    memcpy(&port_rec, &(plaintext[pt_byte_index]) ,sizeof(int));
    pt_byte_index += sizeof(int);

    if(strncmp(authInstance->nickname_client,(char *)client_nickname_rec,NICKNAME_LENGTH)!=0){printf("Mismatch client nickname in M_LISTEN_PORT_CLIENT_P2P\n");return false;}
    if(strncmp(authInstance->nickname_server,(char *)server_nickname_rec,sizeof(NICKNAME_SERVER))!=0){printf("Mismatch server nickname in M_LISTEN_PORT_CLIENT_P2P\n");return false;}
    if(authInstance->expected_opcode < SUCCESSFUL_CLIENT_SERVER_AUTH){printf("Received M_LISTEN_PORT_CLIENT_P2P but not yet authenticated client\n");return false;}

    authInstance->expected_opcode = SUCCESSFUL_CLIENT_AUTHENTICATION_AND_CONFIGURATION;
    *port = port_rec;

    free(client_nickname_rec);
    free(server_nickname_rec);

    return true;
}

Message* create_M_RES_LIST(AuthenticationInstance * authInstance,struct node* head_of_list_users,int user_counter, pthread_mutex_t mutex_list_users){
    //Mex format |op|len|EKas(NONCE_CLIENT list)|
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = M_RES_LIST;

    //get list
    pthread_mutex_lock(&mutex_list_users);
    char * list_buffer; //point to null
    int list_lenght;
    list_buffer = printListInBufferForClient(head_of_list_users,authInstance->nickname_client,user_counter,&list_lenght);
    //list_lenght = prepareListUser(&list_buffer);
    pthread_mutex_unlock(&mutex_list_users);

    //Start creating plaintext |NONCE_CLIENT list|
    unsigned char* plaintext_buffer = (unsigned char *)malloc(NONCE_32 + list_lenght);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nonce_client, NONCE_32);
    pt_byte_index += NONCE_32;

    memcpy(&(plaintext_buffer[pt_byte_index]),list_buffer, list_lenght);
    pt_byte_index += list_lenght;

    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas in M_RES_LIST\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
   
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);

    //Start creating payload |EKas(NONCE_CLIENT list)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);

    return mex;
}

int handler_M_RES_LIST(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance, char** list_buffer){
    //Format mex |op|len|EKas(NONCE_CLIENT list)

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_RES_LIST\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_RES_LIST(plaintext,plaintext_size,authInstance,list_buffer) == false){
        printf("Not consistent info received in M_RES_LIST\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M_RES_LIST(unsigned char * plaintext,int plaintext_size,AuthenticationInstance* authInstance,char** list_buffer){
    //Call on client side

    //declare buffer (NONCE_CLIENT list)
    unsigned char* client_nonce_rec = (unsigned char*)malloc(NONCE_32);
    *list_buffer = (char*)malloc(plaintext_size - NONCE_32);

    int pt_byte_index = 0;

    memcpy(client_nonce_rec,&(plaintext[pt_byte_index]), NONCE_32);
    pt_byte_index += NONCE_32;

    memcpy(*list_buffer, &(plaintext[pt_byte_index]), plaintext_size - NONCE_32);
    pt_byte_index+= plaintext_size - NONCE_32;

    if(memcmp(authInstance->nonce_client,client_nonce_rec,NONCE_32)!=0){printf("Mismatch nonce_client in M_RES_LIST\n");return false;}

    free(client_nonce_rec);

    return true;
}

Message* create_M_REQ_PLAY(char* username_opponent, AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(ID_OPPONENT NONCE_CLIENT)|
    unsigned char* nonce = (unsigned char*)malloc(NONCE_32);
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = M_REQ_PLAY;

    //Start creating plaintext |ID_OPPONENT NONCE_CLIENT|
    unsigned char* plaintext_buffer = (unsigned char *)malloc(NICKNAME_LENGTH + NONCE_32);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]),username_opponent, NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    generate_nonce(&nonce,NONCE_32);

    memcpy(&(plaintext_buffer[pt_byte_index]), &nonce[0], NONCE_32);
    pt_byte_index += NONCE_32;


    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas in M_REQ_PLAY\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
   
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);

    //Start creating payload |EKas(ID_OPPONENT NONCE_CLIENT)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);
    //Adjust authInstance param to save the sent nonce
    memcpy(authInstance->nonce_client,nonce,NONCE_32);
    memcpy(authInstance->nickname_opponent_required, username_opponent, NICKNAME_LENGTH);

    free(nonce);
    return mex;
}

int handler_M_REQ_PLAY(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(ID_OPPONENT NONCE_CLIENT)|

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_REQ_PLAY\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_REQ_PLAY(plaintext,authInstance) == false){
        printf("Not consistent info received in M_REQ_PLAY\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M_REQ_PLAY(unsigned char * plaintext,AuthenticationInstance* authInstance){
    //Call on server side

    unsigned char* opponent_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    unsigned char* nonce_client_rec = (unsigned char*)malloc(NONCE_32);

    int pt_byte_index = 0;

    memcpy(opponent_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    /*memcpy(server_nickname_rec, &(plaintext[pt_byte_index]), sizeof(NICKNAME_SERVER));
    pt_byte_index+= sizeof(NICKNAME_SERVER);*/

    memcpy(nonce_client_rec, &(plaintext[pt_byte_index]) ,NONCE_32);
    pt_byte_index += NONCE_32;

    //if(strncmp(authInstance->nickname_client,(char *)client_nickname_rec,NICKNAME_LENGTH)!=0){printf("Mismatch client nickname in M_REQ_LIST\n");return false;}
    //if(strncmp(authInstance->nickname_server,(char *)server_nickname_rec,sizeof(NICKNAME_SERVER))!=0){printf("Mismatch server nickname in M_REQ_LIST\n");return false;}
    if(authInstance->expected_opcode < SUCCESSFUL_CLIENT_AUTHENTICATION_AND_CONFIGURATION){printf("Received M_REQ_PLAY but not yet authenticated and configured client\n");return false;}

    memcpy(authInstance->nonce_client, nonce_client_rec, NONCE_32);
    memcpy(authInstance->nickname_opponent_required, opponent_nickname_rec, NICKNAME_LENGTH);

    free(nonce_client_rec);
    free(opponent_nickname_rec);
    
    return true;
}

Message* create_M_RES_PLAY_TO_ACK(AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(ID_OPPONENT NONCE_CLIENT NONCE_SERVER)
    unsigned char* nonce = (unsigned char*)malloc(NONCE_32);
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = (char)M_RES_PLAY_TO_ACK; 


    //Start creating plaintext (ID_OPPONENT NONCE_CLIENT NONCE_SERVER)
    unsigned char* plaintext_buffer = (unsigned char *)malloc(NICKNAME_LENGTH + 2 * NONCE_32);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nickname_opponent_required, NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nonce_client, NONCE_32);
    pt_byte_index += NONCE_32;

    generate_nonce(&nonce,NONCE_32);

    memcpy(&(plaintext_buffer[pt_byte_index]), &nonce[0], NONCE_32);
    pt_byte_index += NONCE_32;


    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
    
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);


    //Start creating payload |EKas(ID_OPPONENT NONCE_CLIENT NONCE_SERVER)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);

    //Adjust authInstance param to save the sent nonce
    memcpy(authInstance->nonce_server,nonce,NONCE_32);
    
    free(nonce);
    return mex;
}

int handler_M_RES_PLAY_TO_ACK(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(ID_OPPONENT NONCE_CLIENT NONCE_SERVER)|

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_RES_PLAY_TO_ACK\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_RES_PLAY_TO_ACK(plaintext,authInstance) == false){
        printf("Not consistent info received in M_RES_PLAY_TO_ACK\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M_RES_PLAY_TO_ACK(unsigned char * plaintext,AuthenticationInstance* authInstance){
    //Call on client side |EKas(ID_OPPONENT NONCE_CLIENT NONCE_SERVER)|

    unsigned char* opponent_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    unsigned char* nonce_client_rec = (unsigned char*)malloc(NONCE_32);
    unsigned char* nonce_server_rec = (unsigned char*)malloc(NONCE_32);

    int pt_byte_index = 0;

    memcpy(opponent_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(nonce_client_rec, &(plaintext[pt_byte_index]) ,NONCE_32);
    pt_byte_index += NONCE_32;

    memcpy(nonce_server_rec, &(plaintext[pt_byte_index]) ,NONCE_32);
    pt_byte_index += NONCE_32;

    if(strncmp(authInstance->nickname_opponent_required,(char *)opponent_nickname_rec,NICKNAME_LENGTH)!=0){printf("Mismatch opponent nickname in M_RES_PLAY_TO_ACK\n");return false;}
    if(memcmp(authInstance->nonce_client,nonce_client_rec,NONCE_32)!=0){printf("Mismatch nonce_client in M_RES_PLAY_TO_ACK\n");return false;}
    

    memcpy(authInstance->nonce_server, nonce_server_rec, NONCE_32);

    free(nonce_client_rec);
    free(nonce_server_rec);
    free(opponent_nickname_rec);

    return true;
}


Message* create_M_RES_PLAY_ACK(AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(ID_OPPONENT NONCE_SERVER)

    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = (char)M_RES_PLAY_ACK; 


    //Start creating plaintext (ID_OPPONENT NONCE_SERVER)
    unsigned char* plaintext_buffer = (unsigned char *)malloc(NICKNAME_LENGTH + NONCE_32);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nickname_opponent_required, NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nonce_server, NONCE_32);
    pt_byte_index += NONCE_32;


    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas\n"); return NULL; }

    
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);


    //Start creating payload |EKas(ID_OPPONENT NONCE_SERVER)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    free(ciphertext_and_info_buf);

    return mex;
}

int handler_M_RES_PLAY_ACK(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(ID_OPPONENT NONCE_SERVER)|

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_RES_PLAY_ACK\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_RES_PLAY_ACK(plaintext,authInstance) == false){
        printf("Not consistent info received in M_RES_PLAY_ACK\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M_RES_PLAY_ACK(unsigned char * plaintext,AuthenticationInstance* authInstance){
    //Call on server side |EKas(ID_OPPONENT NONCE_SERVER)|

    unsigned char* opponent_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    unsigned char* nonce_server_rec = (unsigned char*)malloc(NONCE_32);

    int pt_byte_index = 0;

    memcpy(opponent_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(nonce_server_rec, &(plaintext[pt_byte_index]) ,NONCE_32);
    pt_byte_index += NONCE_32;

    if(strncmp(authInstance->nickname_opponent_required,(char *)opponent_nickname_rec,NICKNAME_LENGTH)!=0){printf("Mismatch opponent nickname in M_RES_PLAY_ACK\n");return false;}
    if(memcmp(authInstance->nonce_server,nonce_server_rec,NONCE_32)!=0){printf("Mismatch nonce_server in M_RES_PLAY_ACK\n");return false;}

    free(nonce_server_rec);
    free(opponent_nickname_rec);

    return true;
}


Message* create_M_REQ_ACCEPT_PLAY_TO_ACK(char* username_opponent, AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(ID_OPPONENT NONCE_SERVER)|
    unsigned char* nonce = (unsigned char*)malloc(NONCE_32);
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = M_REQ_ACCEPT_PLAY_TO_ACK;

    //Start creating plaintext |ID_OPPONENT NONCE_SERVER|
    unsigned char* plaintext_buffer = (unsigned char *)malloc(NICKNAME_LENGTH + NONCE_32);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]),username_opponent, NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    generate_nonce(&nonce,NONCE_32);

    memcpy(&(plaintext_buffer[pt_byte_index]), &nonce[0], NONCE_32);
    pt_byte_index += NONCE_32;


    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas in M_REQ_ACCEPT_PLAY_TO_ACK\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
   
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);

    //Start creating payload |EKas(ID_OPPONENT NONCE_SERVER)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);
    //Adjust authInstance param to save the sent nonce
    memcpy(authInstance->nonce_server,nonce,NONCE_32);
    memcpy(authInstance->nickname_opponent_required, username_opponent, NICKNAME_LENGTH);

    free(nonce);
    return mex;
}

int handler_M_REQ_ACCEPT_PLAY_TO_ACK(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(ID_OPPONENT NONCE_SERVER)|

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_REQ_ACCEPT_PLAY_TO_ACK\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_REQ_ACCEPT_PLAY_TO_ACK(plaintext,authInstance) == false){
        printf("Not consistent info received in M_REQ_ACCEPT_PLAY_TO_ACK\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M_REQ_ACCEPT_PLAY_TO_ACK(unsigned char * plaintext,AuthenticationInstance* authInstance){
    //Call on client side

    unsigned char* opponent_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    unsigned char* nonce_server_rec = (unsigned char*)malloc(NONCE_32);

    int pt_byte_index = 0;

    memcpy(opponent_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    /*memcpy(server_nickname_rec, &(plaintext[pt_byte_index]), sizeof(NICKNAME_SERVER));
    pt_byte_index+= sizeof(NICKNAME_SERVER);*/

    memcpy(nonce_server_rec, &(plaintext[pt_byte_index]) ,NONCE_32);
    pt_byte_index += NONCE_32;


    memcpy(authInstance->nonce_server, nonce_server_rec, NONCE_32);
    memcpy(authInstance->nickname_opponent_required, opponent_nickname_rec, NICKNAME_LENGTH);

    free(nonce_server_rec);
    free(opponent_nickname_rec);

    return true;
}


Message* create_M_RES_ACCEPT_PLAY_ACK(char answer, AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(ANSWRE_1BYTE ID_OPPONENT NONCE_SERVER)|

    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = M_RES_ACCEPT_PLAY_ACK;

    //Start creating plaintext |ID_OPPONENT NONCE_SERVER|
    unsigned char* plaintext_buffer = (unsigned char *)malloc(sizeof(char) + NICKNAME_LENGTH + NONCE_32);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]),&answer, sizeof(char));
    pt_byte_index += sizeof(char);

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nickname_opponent_required, NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(&(plaintext_buffer[pt_byte_index]), authInstance->nonce_server, NONCE_32);
    pt_byte_index += NONCE_32;


    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas in M_RES_ACCEPT_PLAY_ACK\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
   
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);

    //Start creating payload |EKas(ID_OPPONENT NONCE_SERVER)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);

    return mex;
}

int handler_M_RES_ACCEPT_PLAY_ACK(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,char* answer){
    //Mex format |op|len|EKas(ANSWRE_1BYTE ID_OPPONENT NONCE_SERVER)|

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_RES_ACCEPT_PLAY_ACK\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_RES_ACCEPT_PLAY_ACK(plaintext,authInstance,answer) == false){
        printf("Not consistent info received in M_RES_ACCEPT_PLAY_ACK\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M_RES_ACCEPT_PLAY_ACK(unsigned char * plaintext,AuthenticationInstance* authInstance, char* answer){
    //Call on server side  (ANSWRE_1BYTE ID_OPPONENT NONCE_SERVER)

    unsigned char* opponent_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    unsigned char* nonce_server_rec = (unsigned char*)malloc(NONCE_32);

    int pt_byte_index = 0;

    memcpy(answer,&(plaintext[pt_byte_index]), sizeof(char));
    pt_byte_index += sizeof(char);

    memcpy(opponent_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;


    memcpy(nonce_server_rec, &(plaintext[pt_byte_index]) ,NONCE_32);
    pt_byte_index += NONCE_32;

    if(strncmp(authInstance->nickname_opponent_required,(char *)opponent_nickname_rec,NICKNAME_LENGTH)!=0){printf("Mismatch opponent nickname in M_RES_ACCEPT_PLAY_ACK\n");return false;}
    if(memcmp(authInstance->nonce_server,nonce_server_rec,NONCE_32)!=0){printf("Mismatch nonce_server in M_RES_ACCEPT_PLAY_ACK\n");return false;}

    free(nonce_server_rec);
    free(opponent_nickname_rec);

    return true;
}



Message* create_M_RES_PLAY_OPPONENT(char response,int opponent_port, AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(RESPONSE_1BYTE OPPONENT_PORT(INT) ID_OPPONENT NONCE_SERVER NONCE_CLIENT)|
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = M_RES_PLAY_OPPONENT;

    //Start creating plaintext |RESPONSE_1BYTE OPPONENT_PORT(INT) ID_OPPONENT NONCE_SERVER NONCE_CLIENT|
    unsigned char* plaintext_buffer = (unsigned char *)malloc(sizeof(char) + sizeof(int) + NICKNAME_LENGTH + 2 * NONCE_32);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]),&response, sizeof(char));
    pt_byte_index += sizeof(char);

    memcpy(&(plaintext_buffer[pt_byte_index]),&opponent_port, sizeof(int));
    pt_byte_index += sizeof(int);

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nickname_opponent_required, NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(&(plaintext_buffer[pt_byte_index]), authInstance->nonce_server, NONCE_32);
    pt_byte_index += NONCE_32;

    memcpy(&(plaintext_buffer[pt_byte_index]), authInstance->nonce_client, NONCE_32);
    pt_byte_index += NONCE_32;


    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas in M_RES_PLAY_OPPONENT\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
   
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);

    //Start creating payload |EKas(RESPONSE_1BYTE OPPONENT_PORT(INT) ID_OPPONENT NONCE_SERVER NONCE_CLIENT)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);

    return mex;
}

int handler_M_RES_PLAY_OPPONENT(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,char* answer,int* opponent_port){
    //Mex format |op|len|EKas(RESPONSE_1BYTE OPPONENT_PORT(INT) ID_OPPONENT NONCE_SERVER NONCE_CLIENT)|

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_RES_PLAY_OPPONENT\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_RES_PLAY_OPPONENT(plaintext,authInstance,answer,opponent_port) == false){
        printf("Not consistent info received in M_RES_PLAY_OPPONENT\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M_RES_PLAY_OPPONENT(unsigned char * plaintext,AuthenticationInstance* authInstance,char* answer,int* opponent_port){
    //Call on client side RESPONSE_1BYTE OPPONENT_PORT(INT) ID_OPPONENT NONCE_SERVER NONCE_CLIENT

    char* response_rec = (char*)malloc(sizeof(char));
    int* opponent_port_rec = (int*)malloc(sizeof(int));
    unsigned char* opponent_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    unsigned char* nonce_server_rec = (unsigned char*)malloc(NONCE_32);
    unsigned char* nonce_client_rec = (unsigned char*)malloc(NONCE_32);

    int pt_byte_index = 0;

    memcpy(response_rec,&(plaintext[pt_byte_index]), sizeof(char));
    pt_byte_index += sizeof(char);

    memcpy(opponent_port_rec,&(plaintext[pt_byte_index]), sizeof(int));
    pt_byte_index += sizeof(int);

    memcpy(opponent_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(nonce_server_rec, &(plaintext[pt_byte_index]) ,NONCE_32);
    pt_byte_index += NONCE_32;

    memcpy(nonce_client_rec, &(plaintext[pt_byte_index]) ,NONCE_32);
    pt_byte_index += NONCE_32;

    //check
    if(strncmp(authInstance->nickname_opponent_required,(char *)opponent_nickname_rec,NICKNAME_LENGTH)!=0){printf("Mismatch opponent nickname in M_RES_PLAY_OPPONENT\n");return false;}
    if(memcmp(authInstance->nonce_server,nonce_server_rec,NONCE_32)!=0){printf("Mismatch nonce_server in M_RES_PLAY_OPPONENT\n");return false;}
    if(memcmp(authInstance->nonce_client,nonce_client_rec,NONCE_32)!=0){printf("Mismatch nonce_client in M_RES_PLAY_OPPONENT\n");return false;}

    //copy params into params
    *answer = *response_rec;
    *opponent_port = *opponent_port_rec;

    free(response_rec);
    free(opponent_port_rec);
    free(opponent_nickname_rec);
    free(nonce_server_rec);
    free(nonce_client_rec);

    return true;
}


Message* create_M_PRELIMINARY_INFO_OPPONENT(EVP_PKEY * opponent_pub_key,AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(ID_LOCAL ID_OPPONENT length_pub_key PUBKeyOPPONENT)
printf("[%s]: in M_PRELIMINARY_INFO_OPPONENT\n",authInstance->nickname_client);
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = M_PRELIMINARY_INFO_OPPONENT; 

    unsigned char* pub_key_buffer = NULL;
    int lenght_pub_key = serialize_PEM_Pub_Key(opponent_pub_key,&pub_key_buffer);

    //Start creating plaintext (ID_LOCAL ID_OPPONENT length_pub_key PUBKeyOPPONENT)
    unsigned char* plaintext_buffer = (unsigned char *)malloc(2 * NICKNAME_LENGTH + sizeof(int) + lenght_pub_key);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nickname_client, NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(&(plaintext_buffer[pt_byte_index]),authInstance->nickname_opponent_required, NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(&(plaintext_buffer[pt_byte_index]), &lenght_pub_key, sizeof(int));
    pt_byte_index += sizeof(int);

    memcpy(&(plaintext_buffer[pt_byte_index]), pub_key_buffer, lenght_pub_key);
    pt_byte_index += lenght_pub_key;

printf("[%s]: in M_PRELIMINARY_INFO_OPPONENT before gcm\n",authInstance->nickname_client);
    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas\n"); return NULL; }
printf("[%s]: in M_PRELIMINARY_INFO_OPPONENT after gcm\n",authInstance->nickname_client);

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
    
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);


    //Start creating payload |EKas(ID_LOCAL ID_OPPONENT length_pub_key PUBKeyOPPONENT)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;

    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);

    free(pub_key_buffer);

    return mex;
}

int handler_M_PRELIMINARY_INFO_OPPONENT(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance,AuthenticationInstanceToPlay * authInstanceToPlay){
    //Mex format |op|len|EKas(ID_LOCAL ID_OPPONENT length_pub_key PUBKeyOPPONENT)|

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_PRELIMINARY_INFO_OPPONENT\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_PRELIMINARY_INFO_OPPONENT(plaintext,authInstance,authInstanceToPlay) == false){
        printf("Not consistent info received in M_PRELIMINARY_INFO_OPPONENT\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M_PRELIMINARY_INFO_OPPONENT(unsigned char * plaintext,AuthenticationInstance* authInstance,AuthenticationInstanceToPlay * authInstanceToPlay){
    //Call on client side |EKas(ID_LOCAL ID_OPPONENT length_pub_key PUBKeyOPPONENT)|

    unsigned char* local_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    unsigned char* opponent_nickname_rec = (unsigned char*)malloc(NICKNAME_LENGTH);
    int length_pub_key;

    int pt_byte_index = 0;

    memcpy(local_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(opponent_nickname_rec,&(plaintext[pt_byte_index]), NICKNAME_LENGTH);
    pt_byte_index += NICKNAME_LENGTH;

    memcpy(&length_pub_key, &(plaintext[pt_byte_index]) ,sizeof(int));
    pt_byte_index += sizeof(int);

    unsigned char* pub_key_buff_rec = (unsigned char*)malloc(length_pub_key);

    memcpy(pub_key_buff_rec, &(plaintext[pt_byte_index]) ,length_pub_key);
    pt_byte_index += length_pub_key;

    
    //deserialize pub_key_rec and copy it in authInstanceToPlay
    authInstanceToPlay->opponent_pub_key = deserialize_PEM_Pub_Key(length_pub_key, pub_key_buff_rec);
    memcpy(authInstanceToPlay->nickname_local, local_nickname_rec, NICKNAME_LENGTH);
    memcpy(authInstanceToPlay->nickname_opponent, opponent_nickname_rec, NICKNAME_LENGTH);


    free(local_nickname_rec);
    free(opponent_nickname_rec);
    free(pub_key_buff_rec);

    return true;
}





Message* create_M_INFORM_SERVER_GAME_START(AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(NONCE_CLIENT)| //otherwise replay attack
    unsigned char* nonce = (unsigned char*)malloc(NONCE_32);
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = M_INFORM_SERVER_GAME_START;

    //Start creating plaintext |NONCE_CLIENT|
    unsigned char* plaintext_buffer = (unsigned char *)malloc(NONCE_32);
    int pt_byte_index = 0;

    generate_nonce(&nonce,NONCE_32);

    memcpy(&(plaintext_buffer[pt_byte_index]), &nonce[0], NONCE_32);
    pt_byte_index += NONCE_32;

    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas in M_INFORM_SERVER_GAME_START\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
    
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);

    //Start creating payload |EKas(NONCE_CLIENT)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);

    //update values in authInstance
    memcpy(authInstance->nonce_client, &nonce[0], NONCE_32);

    free(nonce);

    return mex;
}

int handler_M_INFORM_SERVER_GAME_START(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance){
    //Format mex |op|len|EKas(NONCE_CLIENT)

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_INFORM_SERVER_GAME_START\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_INFORM_SERVER_GAME_START(plaintext,authInstance) == false){
        printf("Not consistent info received in M_INFORM_SERVER_GAME_START\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M_INFORM_SERVER_GAME_START(unsigned char * plaintext,AuthenticationInstance* authInstance){
    //Call on server side

    //declare buffer (NONCE_CLIENT)
    unsigned char* nonce_client_rec = (unsigned char*)malloc(NONCE_32);

    int pt_byte_index = 0;

    memcpy(nonce_client_rec, &(plaintext[pt_byte_index]) ,NONCE_32);
    pt_byte_index += NONCE_32;

    if(authInstance->expected_opcode < SUCCESSFUL_CLIENT_SERVER_AUTH){printf("Received M_INFORM_SERVER_GAME_START but not yet authenticated client\n");return false;}

    memcpy(authInstance->nonce_client, nonce_client_rec, NONCE_32);

    free(nonce_client_rec);
    return true;
}


Message* create_M_INFORM_SERVER_GAME_END(AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(NONCE_CLIENT)| //otherwise replay attack
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = M_INFORM_SERVER_GAME_END;

    //Start creating plaintext |NONCE_CLIENT|
    unsigned char* plaintext_buffer = (unsigned char *)malloc(NONCE_32);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]), authInstance->nonce_client, NONCE_32);
    pt_byte_index += NONCE_32;

    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas in M_INFORM_SERVER_GAME_END\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
    
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);

    //Start creating payload |EKas(NONCE_CLIENT)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;


    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);

    return mex;
}

int handler_M_INFORM_SERVER_GAME_END(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance){
    //Format mex |op|len|EKas(NONCE_CLIENT)

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_INFORM_SERVER_GAME_END\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_INFORM_SERVER_GAME_END(plaintext,authInstance) == false){
        printf("Not consistent info received in M_INFORM_SERVER_GAME_END\nAbort\n");
        return 0;
    }

    return 1;
}

bool get_and_verify_info_M_INFORM_SERVER_GAME_END(unsigned char * plaintext,AuthenticationInstance* authInstance){
    //Call on server side

    //declare buffer (NONCE_CLIENT)
    unsigned char* nonce_client_rec = (unsigned char*)malloc(NONCE_32);

    int pt_byte_index = 0;

    memcpy(nonce_client_rec, &(plaintext[pt_byte_index]) ,NONCE_32);
    pt_byte_index += NONCE_32;

    if(memcmp(authInstance->nonce_client,nonce_client_rec,NONCE_32)!=0){printf("Mismatch nonce_client in M_INFORM_SERVER_GAME_END\n");return false;}
    if(authInstance->expected_opcode < SUCCESSFUL_CLIENT_SERVER_AUTH){printf("Received M_INFORM_SERVER_GAME_END but not yet authenticated client\n");return false;}

    return true;
}


Message* create_M_CLOSE(AuthenticationInstance * authInstance){
    //Mex format |op|len|EKas(Kas)
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
 
    mex->opcode = M_CLOSE;

    //Start creating plaintext |Kas|
    unsigned char* plaintext_buffer = (unsigned char *)malloc(GCM_KEY_SIZE);
    int pt_byte_index = 0;

    memcpy(&(plaintext_buffer[pt_byte_index]), authInstance->symmetric_key, GCM_KEY_SIZE);
    pt_byte_index += GCM_KEY_SIZE;

    //get ciphertext Ekas
    int ciphertext_and_info_buf_size;
    unsigned char* ciphertext_and_info_buf = prepare_gcm_ciphertext(plaintext_buffer, pt_byte_index, authInstance->symmetric_key, &ciphertext_and_info_buf_size);
    if(ciphertext_and_info_buf == NULL){ printf("Error: Unable to create ciphertext Ekas in M_CLOSE\n"); return NULL; }

    //BIO_dump_fp(stdout, (const char *)ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);
    
    //Allocating enough space for the payload
    mex->payload = (unsigned char *)malloc(ciphertext_and_info_buf_size);

    //Start creating payload |EKas(Kas)|
    memcpy(&(mex->payload[byte_index]),ciphertext_and_info_buf, ciphertext_and_info_buf_size);
    byte_index += ciphertext_and_info_buf_size;

    mex->payload_len = byte_index;

    //FREE STUFF!!
    //free(plaintext_buffer); //already freed by get_asymmetric_encrypted_digital_envelope(..)
    free(ciphertext_and_info_buf);

    return mex;
}

int handler_M_CLOSE(unsigned char* payload,unsigned int payload_len,AuthenticationInstance * authInstance){
    //Format mex |op|len|EKas(Kas)

    //get plaintext
    unsigned char* ciphertext = &(payload[0]);
    int ciphertext_size = payload_len;
    int plaintext_size;
    
    unsigned char* plaintext = extract_gcm_ciphertext(ciphertext, ciphertext_size, authInstance->symmetric_key, &plaintext_size);
    if(plaintext == NULL){printf("Error in decryption symmetric ciphertext M_CLOSE\nAbort\n");return 0;}
    //extract and verify info in plaintext
    if(get_and_verify_info_M_CLOSE(plaintext,authInstance) == false){
        printf("Not consistent info received in M_CLOSE\nAbort\n");
        return 0;
    }

    return 1;
}



Message* create_M1_CLIENT_CLIENT_AUTH(AuthenticationInstanceToPlay * authInstanceToPlay){
    //|op|len|ID_LOCAL ID_OPPONENT NONCEa|
    unsigned char *nonce = (unsigned char *)malloc(NONCE_32);
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
    
    mex->opcode = M1_CLIENT_CLIENT_AUTH; 

    mex->payload = (unsigned char *)malloc(2 * NICKNAME_LENGTH + NONCE_32);
    
    //Start creating payload |ID_LOCAL ID_OPPONENT NONCEa|
    memcpy(&(mex->payload[byte_index]),authInstanceToPlay->nickname_local, NICKNAME_LENGTH);
    byte_index += NICKNAME_LENGTH;

    memcpy(&(mex->payload[byte_index]),authInstanceToPlay->nickname_opponent, NICKNAME_LENGTH);
    byte_index += NICKNAME_LENGTH;
    
    generate_nonce(&nonce,NONCE_32);

    memcpy(&(mex->payload[byte_index]), &nonce[0], NONCE_32);
    byte_index += NONCE_32;

    mex->payload_len = byte_index;
    //to debug
    //BIO_dump_fp(stdout, (const char *)mex->payload, mex->payload_len);


    //Initialize values in authInstanceToPlay
    memcpy(authInstanceToPlay->nonce_local, &nonce[0], NONCE_32);

    free(nonce);

    return mex;
}




bool get_and_verify_info_M_CLOSE(unsigned char * plaintext,AuthenticationInstance* authInstance){
    //Call on server side

    //declare buffer (Kas)
    unsigned char* symmetric_key_rec = (unsigned char*)malloc(GCM_KEY_SIZE);

    int pt_byte_index = 0;

    memcpy(symmetric_key_rec,&(plaintext[pt_byte_index]), GCM_KEY_SIZE);
    pt_byte_index += GCM_KEY_SIZE;

    if(memcmp(authInstance->symmetric_key,symmetric_key_rec,GCM_KEY_SIZE)!=0){printf("Mismatch symmetric_key in M_CLOSE\n");return false;}

    memset(symmetric_key_rec,0,GCM_KEY_SIZE);
    free(symmetric_key_rec);

    return true;
}

EVP_PKEY* get_and_verify_pub_key_from_certificate_CLIENT_SIDE(X509* cert_server){
    int ret;

    // load the CA's certificate:
    FILE* cacert_file = fopen("./client_certificate/CA_cert", "r");
    if(!cacert_file){ printf("Error: cannot open CA_cert "); return NULL; }
    X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);
    if(!cacert){ printf("Error: PEM_read_X509 returned NULL\n"); return NULL; }

    // load the CRL:
    FILE* crl_file = fopen("./client_certificate/CA_crl", "r");
    if(!crl_file){ printf("Error: cannot open CA_crl "); return NULL; }
    X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if(!crl){ printf("Error: PEM_read_X509 returned NULL\n"); return NULL; }

    // build a store with the CA's certificate and the CRL:
    X509_STORE* store = X509_STORE_new();
    if(!store) { printf("Error: X509_STORE_new returned NULL\n"); return NULL;} 
    ret = X509_STORE_add_cert(store, cacert);
    if(ret != 1) { printf("Error: X509_STORE_add_cert returned\n"); return NULL;}
    ret = X509_STORE_add_crl(store, crl);
    if(ret != 1) { printf("Error: X509_STORE_add_crl returned\n"); return NULL;}
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) { printf("Error: X509_STORE_set_flags returned\n"); return NULL;}

    // verify the certificate:
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) { printf("Error: X509_STORE_CTX_new returned NULL\n"); return NULL; }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert_server, NULL);
    if(ret != 1) { printf("Error: X509_STORE_CTX_init returned NULL\n"); return NULL; }
    ret = X509_verify_cert(certvfy_ctx);
    if(ret != 1) { printf("Error: X509_verify_cert returned NULL\n"); return NULL; }

    // print the successful verification to screen:
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert_server), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert_server), NULL, 0);

    //TO DO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        //check if correspond to local knowledge of server!

    //
    printf("Certificate of \"%s\" (released by \"%s\") verified successfully\n",tmp,tmp2);
    free(tmp);
    free(tmp2);

    return X509_get_pubkey(cert_server);
}


EVP_PKEY* get_and_verify_pub_key_from_certificate(char * nickname_client){
    int ret;

    // load the CA's certificate:
    FILE* cacert_file = fopen("./server_certificates/CA_cert", "r");
    if(!cacert_file){ printf("Error: cannot open CA_cert "); return NULL; }
    X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);
    if(!cacert){ printf("Error: PEM_read_X509 returned NULL\n"); return NULL; }

    // load the CRL:
    FILE* crl_file = fopen("./server_certificates/CA_crl", "r");
    if(!crl_file){ printf("Error: cannot open CA_crl "); return NULL; }
    X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if(!crl){ printf("Error: PEM_read_X509 returned NULL\n"); return NULL; }

    // build a store with the CA's certificate and the CRL:
    X509_STORE* store = X509_STORE_new();
    if(!store) { printf("Error: X509_STORE_new returned NULL\n"); return NULL;} 
    ret = X509_STORE_add_cert(store, cacert);
    if(ret != 1) { printf("Error: X509_STORE_add_cert returned\n"); return NULL;}
    ret = X509_STORE_add_crl(store, crl);
    if(ret != 1) { printf("Error: X509_STORE_add_crl returned\n"); return NULL;}
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) { printf("Error: X509_STORE_set_flags returned\n"); return NULL;}

    //Build file name
    char certificate_file_name[NICKNAME_LENGTH + 30]; //format ./server_certificate/nickname_cert.pem
	strcpy(certificate_file_name,"./server_certificates/");
	strncat(certificate_file_name,nickname_client,NICKNAME_LENGTH);
	strcat(certificate_file_name,"_cert.pem");

    //printf("certificate-file_name->\n %s\n",certificate_file_name);

    //open file to get the certificate
    FILE* cert_file = fopen(certificate_file_name, "r");
    if(!cert_file){ printf("Error: Certificate NOT FOUND!\n"); return NULL;}
    X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(!cert){ printf("Error: PEM_read_X509 returned NULL\n"); return NULL; }

    // verify the certificate:
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) { printf("Error: X509_STORE_CTX_new returned NULL\n"); return NULL; }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
    if(ret != 1) { printf("Error: X509_STORE_CTX_init returned NULL\n"); return NULL; }
    ret = X509_verify_cert(certvfy_ctx);
    if(ret != 1) { printf("Error: X509_verify_cert returned NULL\n"); return NULL; }

    // print the successful verification to screen:
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    printf("Certificate of \"%s\" (released by \"%s\") verified successfully\n",tmp,tmp2);
    free(tmp);
    free(tmp2);

    return X509_get_pubkey(cert);
}

int serialize_PEM_Pub_Key(EVP_PKEY* pubkey,unsigned char** pub_key_buffer){
    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio,pubkey);
    int returning_size = BIO_get_mem_data(mbio,pub_key_buffer);
    //BIO_dump_fp(stdout, (const char *)*pub_key_buffer, returning_size);
    return returning_size;
}

EVP_PKEY* deserialize_PEM_Pub_Key(int pubkey_size,unsigned char* pubkey_buf){
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio,pubkey_buf,pubkey_size);
    EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(mbio,NULL,NULL,NULL);
    return pubkey;
}

unsigned char* get_asymmetric_encrypted_digital_envelope(unsigned char* clear_buf, int clear_size, EVP_PKEY* pubkey, int* returning_size){
    // declare some useful variables:
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    int encrypted_key_len = EVP_PKEY_size(pubkey);
    int iv_len = EVP_CIPHER_iv_length(cipher);
    int block_size = EVP_CIPHER_block_size(cipher);

    // create the envelope context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){printf("Error: EVP_CIPHER_CTX_new returned NULL\n"); return NULL; }

    // allocate buffers for encrypted key and IV:
    unsigned char* encrypted_key = (unsigned char*)malloc(encrypted_key_len);
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    if(!encrypted_key || !iv) {printf("Error: malloc returned NULL (encrypted key too big?)\n"); return NULL; }

    // check for possible integer overflow in (clear_size + block_size)
    // (possible if the plaintext is too big, assume non-negative clear_size and block_size):
    if(clear_size > INT_MAX - block_size) { printf("Error: integer overflow (file too big?)\n"); return NULL; }

    // allocate a buffer for the ciphertext:
    int enc_buffer_size = clear_size + block_size;
    unsigned char* cphr_buf = (unsigned char*)malloc(enc_buffer_size);
    if(!cphr_buf) {printf("Error: malloc returned NULL (file too big?)\n"); return NULL; }

    // encrypt the plaintext:
    // (perform a single update on the whole plaintext since not huge)
    //Since only one destinatore => 1 as input param
    int ret = EVP_SealInit(ctx, cipher, &encrypted_key, &encrypted_key_len, iv, &pubkey, 1);
    if(ret <= 0){ // it is "<=0" to catch the (undocumented) case of -1 return value, when the operation is not supported (e.g. attempt to use digital envelope with Elliptic Curve keys)
        printf("Error: EVP_SealInit returned %d \n", ret);
        return NULL;
    }

    int nc = 0; // bytes encrypted at each chunk
    int nctot = 0; // total encrypted bytes
    ret = EVP_SealUpdate(ctx, cphr_buf, &nc, clear_buf, clear_size);  
    if(ret == 0){printf("Error: EVP_SealUpdate returned %d\n",ret); return NULL; }
    nctot += nc;
    ret = EVP_SealFinal(ctx, cphr_buf + nctot, &nc);
    if(ret == 0){printf("Error: EVP_SealFinal returned %d\n",ret); return NULL; }
    nctot += nc;
    int cphr_size = nctot;

    //declare buffer for: encrypted key, IV, ciphertext
    *returning_size = encrypted_key_len + iv_len + cphr_size;
    unsigned char * buffer_to_return = (unsigned char *)malloc(*returning_size);

    //build buffer to return
    int byte_index = 0;
    memcpy(&(buffer_to_return[byte_index]),encrypted_key, encrypted_key_len);
    byte_index += encrypted_key_len;

    memcpy(&(buffer_to_return[byte_index]),iv, iv_len);
    byte_index += iv_len;

    memcpy(&(buffer_to_return[byte_index]),cphr_buf, cphr_size);
    byte_index += cphr_size;

    // delete the symmetric key and the plaintext from memory:
    EVP_CIPHER_CTX_free(ctx);
    //#pragma optimize("", off) IT'S IGNORED
    memset(clear_buf, 0, clear_size);
    //#pragma optimize("", on)
    free(clear_buf);

    // deallocate buffers:
    free(cphr_buf);
    free(encrypted_key);
    free(iv);
    EVP_PKEY_free(pubkey);

    return buffer_to_return;
}

unsigned char* get_asymmetric_decrypted_digital_envelope(unsigned char* ciphertext_and_info_buf, int ciphertext_and_info_buf_size, EVP_PKEY* prvkey, int* returning_size){
    // declare some useful variables:
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    int encrypted_key_len = EVP_PKEY_size(prvkey);
    int iv_len = EVP_CIPHER_iv_length(cipher);

    // check for possible integer overflow in (encrypted_key_len + iv_len)
    // (theoretically possible if the encrypted key is too big):
    if(encrypted_key_len > INT_MAX - iv_len) {printf("Error: integer overflow (encrypted key too big?)\n"); return NULL; }
    // check for correct format of the encrypted file
    // (size must be >= encrypted key size + IV + 1 block):
    if(ciphertext_and_info_buf_size < encrypted_key_len + iv_len) {printf("Error: encrypted file with wrong format\n"); return NULL; }

    // allocate buffers for encrypted key, IV, ciphertext, and plaintext:
    unsigned char* encrypted_key = (unsigned char*)malloc(encrypted_key_len);
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    int cphr_size = ciphertext_and_info_buf_size - encrypted_key_len - iv_len;
    unsigned char* cphr_buf = (unsigned char*)malloc(cphr_size);
    unsigned char* clear_buf = (unsigned char*)malloc(cphr_size);
    if(!encrypted_key || !iv || !cphr_buf || !clear_buf) {printf("Error: malloc returned NULL (file too big?)\n"); return NULL; }

    //retrieve encrypted key, IV, ciphertext
    int byte_index = 0;
    memcpy(encrypted_key,&(ciphertext_and_info_buf[byte_index]), encrypted_key_len);
    byte_index += encrypted_key_len;

    memcpy(iv, &(ciphertext_and_info_buf[byte_index]), iv_len);
    byte_index += iv_len;

    memcpy(cphr_buf, &(ciphertext_and_info_buf[byte_index]), cphr_size);
    byte_index += cphr_size;

    // create the envelope context:
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){printf("Error: EVP_CIPHER_CTX_new returned NULL\n"); return NULL; }

    // decrypt the ciphertext:
    // (perform a single update on the whole ciphertext since not huge)
    int ret = EVP_OpenInit(ctx, cipher, encrypted_key, encrypted_key_len, iv, prvkey);
    if(ret == 0){printf("Error: EVP_OpenInit returned %d\n",ret); return NULL; }
    int nd = 0; // bytes decrypted at each chunk
    int ndtot = 0; // total decrypted bytes
    ret = EVP_OpenUpdate(ctx, clear_buf, &nd, cphr_buf, cphr_size);
    if(ret == 0){printf("Error: EVP_OpenUpdate returned %d\n",ret); return NULL; }
    ndtot += nd;
    ret = EVP_OpenFinal(ctx, clear_buf + ndtot, &nd);
    if(ret == 0){printf("Error: EVP_OpenFinal returned %d\n",ret); return NULL; }
    ndtot += nd;
    int clear_size = ndtot;

    // delete the symmetric key //not privkey since reused for client to client auth -- otherwise each time re-type password to load again
    //Only at client quit delete privkey
    EVP_CIPHER_CTX_free(ctx);

    // deallocate buffers:
    free(encrypted_key);
    free(iv);
    free(cphr_buf);

    *returning_size = clear_size;
    return clear_buf;
}

void generate_symmetric_key(unsigned char **key,unsigned long key_len){
	RAND_poll();
	int rc = RAND_bytes(*key, key_len);
	//unsigned long err = ERR_get_error();

	if(rc != 1) {
		printf("Error in generating key\n");
		exit(1);
	}
}

bool server_authentication(EVP_PKEY** p_prvkey){
	//find server_key.pem														   		//	22			   //11111111 = 8
	char prvkey_file_name[sizeof(NICKNAME_SERVER) + 30]; //format ./server_certificates/server_key.pem
	strcpy(prvkey_file_name,"./server_certificates/");
	strcat(prvkey_file_name,NICKNAME_SERVER);
	strcat(prvkey_file_name,"_key.pem");
	//printf("File to open %s\n",prvkey_file_name);

	// load my private key:
	FILE* prvkey_file = fopen(prvkey_file_name, "r");
	if(!prvkey_file){ printf("Error: Unknown file to load for server authentication\n"); return false;}
	*(p_prvkey) = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
	fclose(prvkey_file);
	if(!*(p_prvkey)){ printf("Error: Wrong password\n"); return false;}

	return true;
}

bool client_authentication(char* username_client,EVP_PKEY** p_prvkey){
	char buffer_nickname[NICKNAME_LENGTH];
	printf("**Authentication**\nUsername -> ");
	fgets(buffer_nickname, NICKNAME_LENGTH, stdin);
	sscanf(buffer_nickname, "%s", username_client);
	username_client[NICKNAME_LENGTH-1]='\0';
															   		//	21			 //11111111 = 8
	char prvkey_file_name[NICKNAME_LENGTH + 29]; //format ./client_certificate/nickname_key.pem
	strcpy(prvkey_file_name,"./client_certificate/");
	strncat(prvkey_file_name,username_client,NICKNAME_LENGTH);
	strcat(prvkey_file_name,"_key.pem");
	//printf("File to open %s\n",prvkey_file_name);

	// load my private key:
	FILE* prvkey_file = fopen(prvkey_file_name, "r");
	if(!prvkey_file){ printf("Error: Unknown Username\n"); return false;}
	*(p_prvkey) = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
	fclose(prvkey_file);
	if(!*(p_prvkey)){ printf("Error: Wrong password\n"); return false;}

	return true;
}

bool send_MESSAGE(int sock, Message* mex){
    if(mex == NULL)
        return false;
    unsigned char* buffer_to_send = (unsigned char *)malloc(mex->payload_len);
	int byte_to_send = add_header(buffer_to_send,mex->opcode,mex->payload_len,mex->payload);
	int byte_correctly_sent = send(sock, buffer_to_send, byte_to_send, 0);
    //BIO_dump_fp(stdout, (const char *)buffer_to_send, byte_to_send);
    //free(buffer_to_send);
    return byte_correctly_sent == byte_to_send?true:false;
}

bool read_MESSAGE(int sock, Message* mex_received){
    read(sock, &mex_received->opcode, OPCODE_SIZE);
    //Retrieve remaining part of message (payload_len)
    read(sock, &mex_received->payload_len, PAYLOAD_LEN_SIZE);
    mex_received->payload = (unsigned char *)malloc(mex_received->payload_len);
    //Retrieve remaining part of message (payload)
    int read_byte = read(sock, mex_received->payload, mex_received->payload_len);
    return read_byte == mex_received->payload_len?true:false;
}

bool read_MESSAGE_payload(int sock, Message* mex_received){
    read(sock, &mex_received->payload_len, PAYLOAD_LEN_SIZE);
    mex_received->payload = (unsigned char *)malloc(mex_received->payload_len);
    //Retrieve remaining part of message (payload)
    int read_byte = read(sock, mex_received->payload, mex_received->payload_len);
    return read_byte == mex_received->payload_len?true:false;
}