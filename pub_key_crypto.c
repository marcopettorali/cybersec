/*
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include"pub_key_crypto.h"

EVP_PKEY* get_and_verify_pub_key_from_certificate(AuthenticationInstance * authInstance){
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
	strcpy(certificate_file_name,"./server_certificate/");
	strncat(certificate_file_name,authInstance->nickname_client,NICKNAME_LENGTH);
	strcat(certificate_file_name,"_cert.pem");
    
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
}*/