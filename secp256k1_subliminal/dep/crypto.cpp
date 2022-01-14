#include "crypto.h"
#include "serialize.h"

#include <iostream>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "scalar.h"

#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
using namespace CryptoPP;

ucharbuf serialize(Pubkey& in, bool compress)
{
    ucharbuf out;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char pk[65];
    size_t len = 65;
    if(compress){
	secp256k1_ec_pubkey_serialize(ctx, pk, &len, &in, SECP256K1_EC_COMPRESSED);
    } else{
	secp256k1_ec_pubkey_serialize(ctx, pk, &len, &in, SECP256K1_EC_UNCOMPRESSED);
    }
    if(compress){
        out.assign(pk, pk+33);
    } else{
        out.assign(pk, pk+65);
    }
    secp256k1_context_destroy(ctx);
    return out;
}

bool parse(Pubkey& pk, ucharbuf& in)
{
    bool ret = false;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if(secp256k1_ec_pubkey_parse(ctx, &pk, &in[0], in.size())){
        ret = true;
    }
    secp256k1_context_destroy(ctx);
    return ret;
}

ucharbuf to_buf(Seckey& i)
{
    ucharbuf out;
    out.assign(i.keydata, i.keydata+32);
    return out;
}

ucharbuf to_buf(Signature& i)
{
    ucharbuf out;
    out.assign(i.data, i.data+64);
    return out;
}

void gen_random(unsigned char* ptr, size_t cnt)
{
    int urandom = open("/dev/urandom", O_RDONLY);
    size_t random_bytes = read(urandom, ptr, cnt);
    if(random_bytes != cnt){
        fprintf(stderr, "Cannot get random!\n");
        exit(-1);
    }
    close(urandom);
}

bool gen_keypair(Pubkey& pk, Seckey& sk)
{
    FILE* fp = fopen("/dev/urandom", "r");
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    for(int i = 0; i < 100; i++){
        if(fread(sk.keydata, 1, 32, fp) == 32){
            if(secp256k1_ec_seckey_verify(ctx, sk.keydata)){
                if(secp256k1_ec_pubkey_create(ctx, &pk, sk.keydata)){
                    secp256k1_context_destroy(ctx);
                    fclose(fp);
                    return true;
                }
            }
        }
        // gen a new random num as sk
        // check validality of this sk, if valid then gen pk and ret
    }
    secp256k1_context_destroy(ctx);
    fclose(fp);
    return false;
}

bool pk_from_sk(Pubkey& pk, Seckey& sk)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if(secp256k1_ec_seckey_verify(ctx, sk.keydata)){
        if(secp256k1_ec_pubkey_create(ctx, &pk, sk.keydata)){
            secp256k1_context_destroy(ctx);
            return true;
        }
    }
    secp256k1_context_destroy(ctx);
    return false;
}

void hash(unsigned char* digest, ucharbuf& buf)
{
    SHA256 sha;
    sha.CalculateDigest(digest, &buf[0], buf.size());
}
ucharbuf hash(ucharbuf& buf)
{
    unsigned char digest_raw[SHA_LENGTH];
    hash(digest_raw, buf);
    ucharbuf digest;
    digest.assign(digest_raw, digest_raw+SHA_LENGTH);
    return digest;
}


int hash_sign(ucharbuf& der_sig, ucharbuf& buf, Seckey& seckey_struct, unsigned char* secmsg)
{
    unsigned char* seckey = seckey_struct.keydata;
    int ret = 1;
    unsigned char digest[SHA_LENGTH];
    secp256k1_ecdsa_signature sig;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    hash(digest, buf);
    if(!secp256k1_ecdsa_sign_withmsg(ctx, &sig, digest, seckey, secmsg)){
        ret = 0;
    }
    unsigned char serialized[150];
    size_t len = 150;
    secp256k1_ecdsa_signature_serialize_der(ctx, serialized, &len, &sig);
    secp256k1_context_destroy(ctx);
    der_sig.assign(serialized, serialized+len);
    
    return ret; 
}

int hash_sign(ucharbuf& der_sig, ucharbuf& buf, Seckey& seckey_struct)
{
    unsigned char* seckey = seckey_struct.keydata;
    int ret = 1;
    unsigned char digest[SHA_LENGTH];
    secp256k1_ecdsa_signature sig;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    hash(digest, buf);
    if(secp256k1_ecdsa_sign(ctx, &sig, digest, seckey, NULL, NULL) == 0){
        fprintf(stderr, "Error: failed to create signature.\n");
        ret = 0;
    }
    unsigned char serialized[150];
    size_t len = 150;
    secp256k1_ecdsa_signature_serialize_der(ctx, serialized, &len, &sig);
    secp256k1_context_destroy(ctx);
    der_sig.assign(serialized, serialized+len);
    return ret;
}

bool hash_verify(ucharbuf& buf, 
                 ucharbuf& der_sig, 
                 secp256k1_pubkey& pubkey)
{
    bool ret = false;
    unsigned char digest[SHA_LENGTH];
    secp256k1_ecdsa_signature sig;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if(secp256k1_ecdsa_signature_parse_der(ctx, &sig, &der_sig[0], der_sig.size())){
        hash(digest, buf);
        if(secp256k1_ecdsa_verify(ctx, &sig, digest, &pubkey)){
            ret = true;
        } else{
            // fprintf(stderr, "verify failed.");
        }
    } else{
        // fprintf(stderr, "Error: failed to parse signature.\n");
    }
    
    secp256k1_context_destroy(ctx);
    return ret;
}

bool hash_verify(unsigned char* secmsg, 
                 ucharbuf& buf, 
                 ucharbuf& der_sig,
                 Seckey& seckey_struct)
{
    unsigned char* seckey = seckey_struct.keydata;
    bool ret = false;
    secp256k1_pubkey pubkey;
    unsigned char digest[SHA_LENGTH];
    hash(digest, buf);
    secp256k1_ecdsa_signature sig;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)){
        if(secp256k1_ecdsa_signature_parse_der(ctx, &sig, &der_sig[0], der_sig.size())){
            if(secp256k1_ecdsa_verify_withmsg(ctx, &sig, digest, &pubkey, seckey, secmsg)){
                ret = true;
            }
        }
    }
    
    secp256k1_context_destroy(ctx);
    return ret;
}   

