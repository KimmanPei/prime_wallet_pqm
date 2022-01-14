#include "crypto_c.h"
#include "crypto.h"

void cleanup(void* p)
{
    free(p);    
}

int C_pubKeyParse(unsigned char* pk_data, char* data, int len)
{   
    Pubkey pk;
    ucharbuf buf;
    buf.assign((unsigned char*)data, (unsigned char*)data+len);
    if(parse(pk, buf)){
        for(int i = 0; i < 64; i++){
            pk_data[i] = pk.data[i];
        }
        return 1;
    } else{
        return 0;
    }
}

int C_genKeypair(char* pk_raw, char* sk_raw)
{
    Pubkey pk;
    Seckey sk;
    if(gen_keypair(pk, sk)){
        for(int i = 0; i < 64; i++){
            pk_raw[i] = pk.data[i];
        }
        for(int i = 0; i < 32; i++){
            sk_raw[i] = sk.keydata[i];
        }
        return 1;
    } else{
        return 0;
    }
}

void C_pubkeySerialize(char* buf, char* pk_raw, int compress)
{
    Pubkey pk;
    for(int i = 0; i < 64; i++){
        pk.data[i] = pk_raw[i];
    }
    bool comp{compress == 1};
    ucharbuf ubuf = serialize(pk, comp);
    for(int i = 0; i < ubuf.size(); i++){
        buf[i] = ubuf[i];
    }
}

int C_pkFromSk(char* pk_raw, char* sk_raw)
{
    Pubkey pk;
    Seckey sk;
    for(int i = 0; i < 32; i++){
        sk.keydata[i] = sk_raw[i];
    }
    if(pk_from_sk(pk, sk)){
        for(int i = 0; i < 64; i++){
            pk_raw[i] = pk.data[i];
        }
        return 1;
    } else{
        return 0;
    }
}

int C_hashSign(char* sig_buf,
               int* sig_sz,
               char* data_raw, 
               int data_sz, 
               char* sk_raw)
{
    ucharbuf data_v;
    data_v.assign(data_raw, data_raw+data_sz);
    
    ucharbuf sig;
    
    Seckey sk;
    for(int i = 0; i < 32; i++){
        sk.keydata[i] = sk_raw[i];
    }
    
    int ret = hash_sign(sig, data_v, sk);
    if(ret){
        for(int i = 0; i < sig.size(); i++){
            sig_buf[i]= sig[i];
        }
        *sig_sz = sig.size();
    } 
    return ret;
}

int C_hashSignWithMsg(char* sig_buf,
                      int* sig_sz,
                      char* data_raw, 
                      int data_sz, 
                      char* sk_raw,
                      char* msg)
{
    ucharbuf data_v;
    data_v.assign(data_raw, data_raw+data_sz);
    
    ucharbuf sig;
    
    Seckey sk;
    for(int i = 0; i < 32; i++){
        sk.keydata[i] = sk_raw[i];
    }
    
    int ret = hash_sign(sig, data_v, sk, (unsigned char*)msg);
    if(ret){
        for(int i = 0; i < sig.size(); i++){
            sig_buf[i]= sig[i];
        }
        *sig_sz = sig.size();
    } 
    return ret;
}

int C_hashVerify(char* data_raw,
                 int data_sz,
                 char* sig_raw,
                 int sig_sz,
                 char* pk_raw)
{
    ucharbuf data;
    ucharbuf sig;
    Pubkey pk;
    
    data.assign(data_raw, data_raw+data_sz);
    sig.assign(sig_raw, sig_raw+sig_sz);
    for(int i = 0; i < 64; i++){
        pk.data[i] = pk_raw[i];
    }
    
    if(hash_verify(data, sig, pk)){
        return 1;
    } else{
        return 0;
    }
}

int C_hashVerifyWithMsg(char* msg,
                        char* data_raw,
                        int data_sz,
                        char* sig_raw,
                        int sig_sz,
                        char* sk_raw)
{
    ucharbuf data;
    ucharbuf sig;
    Seckey sk;
    
    data.assign(data_raw, data_raw+data_sz);
    sig.assign(sig_raw, sig_raw+sig_sz);
    for(int i = 0; i < 32; i++){
        sk.keydata[i] = sk_raw[i];
    }
    
    if(hash_verify((unsigned char*)msg, data, sig, sk)){
        return 1;
    } else{
        return 0;
    }
}
