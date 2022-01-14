#ifndef CRYPTO_C_H
#define CRYPTO_C_H

extern "C"{

#include <stdlib.h>
    
int C_pubKeyParse(unsigned char* pk_data, 
                  char* data, 
                  int len);

int C_genKeypair(char* pk, char* sk);

void C_pubkeySerialize(char* buf, char* pk_raw, int compress);

void cleanup(void* p);

int C_pkFromSk(char* pk_raw, char* sk_raw);

int C_hashSign(char* sig_buf,
               int* sig_sz,
               char* data_raw, 
               int data_sz, 
               char* sk_raw);

int C_hashSignWithMsg(char* sig_buf,
                      int* sig_sz,
                      char* data_raw, 
                      int data_sz, 
                      char* sk_raw,
                      char* msg);

int C_hashVerify(char* data_raw,
                 int data_sz,
                 char* sig_raw,
                 int sig_sz,
                 char* pk);

int C_hashVerifyWithMsg(char* msg,
                        char* data_raw,
                        int data_sz,
                        char* sig_raw,
                        int sig_sz,
                        char* sk);
}

#endif
