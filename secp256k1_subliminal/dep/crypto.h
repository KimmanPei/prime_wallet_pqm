#ifndef CRYPTO_H
#define CRYPTO_H

#include "secp256k1.h"
#include "serialize.h"
#include <cryptopp/sha.h>
#include <cryptopp/ripemd.h>

#define SHA_LENGTH 32

using Pubkey = secp256k1_pubkey;

ucharbuf to_buf(Pubkey& i);
inline ucharbuf to_buf(Pubkey&& i)
{Pubkey b{i}; return to_buf(b);}

ucharbuf serialize(Pubkey& i, bool compress);
inline ucharbuf serialize(Pubkey&& i, bool compress)
    {Pubkey t{i}; return serialize(t, compress);}
bool parse(Pubkey& pk, ucharbuf& in);

struct Seckey
{unsigned char keydata[32];};

ucharbuf to_buf(Seckey& i);
inline ucharbuf to_buf(Seckey&& i)
{Seckey b{i}; return to_buf(b);}

using Signature = secp256k1_ecdsa_signature;

ucharbuf to_buf(Signature& i);
inline ucharbuf to_buf(Signature&& i)
{Signature b{i}; return to_buf(b);}

void gen_random(unsigned char* ptr, size_t cnt);

bool gen_keypair(Pubkey& pk, Seckey& sk);
bool pk_from_sk(Pubkey& pk, Seckey& sk);

void hash(unsigned char* digesy, ucharbuf& buf);
ucharbuf hash(ucharbuf& buf);

int hash_sign(ucharbuf& der_sig, 
              ucharbuf& buf, 
              Seckey& seckey, 
              unsigned char* secmsg);

int hash_sign(ucharbuf& der_sig, 
              ucharbuf& data, 
              Seckey& seckey);

bool hash_verify(ucharbuf& buf, 
                 ucharbuf& der_sig, 
                 Pubkey& pubkey);


bool hash_verify(unsigned char* secmsg, 
                 ucharbuf& buf, 
                 ucharbuf& der_sig, 
                 Seckey& seckey);
#endif
