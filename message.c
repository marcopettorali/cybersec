#include <stdio.h>
#include<stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "message.h"
#include "util.h"


void generate_nonce(unsigned char **nonce,unsigned long nonce_len){
	RAND_poll();
	int rc = RAND_bytes(*nonce, nonce_len);
	//unsigned long err = ERR_get_error();

	if(rc != 1) {
		printf("Error in generating nonce\n");
		exit(1);
	}
}

Message* create_M1_CLIENT_SERVER_AUTH(char* username_client){
    unsigned char *nonce = (unsigned char *)malloc(NONCE_32);
    int byte_index = 0;
    //create returning mex
    Message *mex = (Message *)malloc (sizeof (Message));
    
    mex->opcode = M1_CLIENT_SERVER_AUTH; 

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