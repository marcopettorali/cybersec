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
    int offset = 0;
    unsigned char nonce[32];
	//generate_nonce(&nonce,sizeof(nonce));
    RAND_bytes(nonce, 32);

	unsigned char payload[NICKNAME_LENGTH + NICKNAME_SERVER + NONCE_32];
    
    int username_lenght= strlen(username_client) + 1;
    memcpy(payload,username_client,username_lenght);
    offset+=username_lenght;
    memcpy(payload + offset," ",1);
    offset+= 1;

    memcpy(payload + offset,"server",strlen("server")+1);
    offset+=strlen("server")+ 1;
    memcpy(payload + offset," ",1);
    offset+= 1;

    memcpy(payload + offset,nonce,NONCE_32);
    offset+=NONCE_32;
    

    BIO_dump_fp (stdout, (const char *)payload, offset);

    //scrive graziano.
    //create mex
}