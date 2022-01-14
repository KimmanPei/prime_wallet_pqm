import random
from decimal import Decimal
from queue import Queue

import numpy
import numpy as np

import DB_insert
import DB_select
import pyDH
from ecdsa import SigningKey, SECP256k1, VerifyingKey, util
import base58
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long

import ether_client
import litecoin_client
from secp256k1_subliminal.tools import *
import bitcoin_client
import sha3
import time


def gen_keypair():
    sk = SigningKey.generate(curve=SECP256k1)
    pk = sk.get_verifying_key()
    return sk, pk


def get_pk_from_skbytes(sk_b):
    sk = recover_sk_fromstr(sk_b)
    pk = sk.get_verifying_key()
    return pk


def get_uncompressed_pkbytes(pk):
    pk_bytes = pk.to_string("uncompressed")
    return pk_bytes


def get_skbytes(sk):
    sk_bytes = sk.to_string()
    return sk_bytes


# return the bytes type of pk and sk
# pk_bytes with 0x02/0x03 prefix
def get_byteskeypair(pk, sk):
    sk_bytes = sk.to_string()
    pk_bytes = pk.to_string("compressed")
    return pk_bytes, sk_bytes


# return type: bytes
def get_wifsk(sk_b):
    # mainnet:0x80,testnet and regtest :0xef
    # if the sk corresponds to a compressed public key, add 0x01 in the end
    rk = bytes.fromhex('ef') + sk_b + bytes.fromhex('01')
    checksum = hashlib.sha256(hashlib.sha256(rk).digest()).digest()[0:4]
    rk = rk + checksum
    return base58.b58encode(rk)


# recover pk,sk from raw encoding
def recover_pk_fromstr(pk_byte):
    pk = VerifyingKey.from_string(pk_byte, curve=SECP256k1)
    return pk


def recover_sk_fromstr(sk_byte):
    sk = SigningKey.from_string(sk_byte, curve=SECP256k1)
    return sk


# return the result before base58 encoding,type:bytes,length:25 bytes
def get_btc_pkhash(pk, type):
    pk_bytes = pk.to_string("compressed")
    r1 = hashlib.sha256()
    r1.update(pk_bytes)
    r2 = hashlib.new('ripemd160', r1.digest())
    if type == 'mainnet':
        version = '00'
    elif type == 'testnet' or 'regtest':
        version = '6f'
    else:
        raise Exception("error address type")
    ver_bytes = bytes.fromhex(version)
    r2_bytes = ver_bytes + r2.digest()

    r3 = hashlib.sha256()
    r3.update(r2_bytes)
    r3_bytes = r3.digest()
    r3_final = hashlib.sha256()
    r3_final.update(r3_bytes)
    r3final_bytes = r3_final.digest()
    front4bytes = r3final_bytes[:4]

    pkhash = r2_bytes + front4bytes
    return pkhash


def get_ltc_pkhash(pk, nettype):
    pk_bytes = pk.to_string("compressed")
    r1 = hashlib.sha256()
    r1.update(pk_bytes)
    r2 = hashlib.new('ripemd160', r1.digest())
    if nettype == 'mainnet':
        version = '30'
    elif nettype == 'testnet' or 'regtest':
        version = '6f'
    else:
        raise Exception("error address type")
    ver_bytes = bytes.fromhex(version)
    r2_bytes = ver_bytes + r2.digest()

    r3 = hashlib.sha256()
    r3.update(r2_bytes)
    r3_bytes = r3.digest()
    r3_final = hashlib.sha256()
    r3_final.update(r3_bytes)
    r3final_bytes = r3_final.digest()
    front4bytes = r3final_bytes[:4]

    pkhash = r2_bytes + front4bytes
    return pkhash


# 20bits,type is bytes
def get_btc_pkscript(pk, nettype):
    pkhash = get_btc_pkhash(pk, nettype)
    return pkhash[1:21]


def get_ltc_pkscript(pk, nettype):
    pkhash = get_ltc_pkhash(pk, nettype)
    return pkhash[1:21]


# use pkhash to generate a bitcoin/litecoin P2PKH address,type:string
def gen_address(pk, nettype, coin_name):
    if coin_name == 'bitcoin':
        pkhash = get_btc_pkhash(pk, nettype)
    elif coin_name == 'litecoin':
        pkhash = get_ltc_pkhash(pk, nettype)
    address = base58.b58encode(pkhash)
    return address.decode("utf-8")


def recover_btc_pkhash(address):
    pkhash = base58.b58decode(address)
    return pkhash


def recover_ltc_pkhash(address):
    pkhash = base58.b58decode(address)
    return pkhash

# etheruem address's generating process has no difference between mainnet and testnet
# return type is bytes
def get_eth_address(pk):
    pk_bytes = get_uncompressed_pkbytes(pk)
    # remove 0x04 from pk_bytes before hash
    pkhash = sha3.keccak_256(pk_bytes[1:]).digest()
    address_bytes = pkhash[-20:]
    return address_bytes


def get_pkscript_by_addr(address):
    pkhash = base58.b58decode(address)
    pk_script = pkhash[1:21] # delete the first byte of pkhash
    return pk_script


# get the first 16 bits of pkscript in int type
def get_hashid(pkscript):
    # pkscript = get_btc_pkscript(pk)
    hash_bytes = pkscript[:2]
    hash_int = int.from_bytes(hash_bytes, "big")
    return hash_int


def recover_hashbytes(hash_int):
    hash_bytes = int.to_bytes(hash_int, 2, "big") # 2 is the length of bytes after transforming
    return hash_bytes


# type:bytes
def gen_AESkey():
    key = get_random_bytes(16)
    return key


# result and all the params are bytes type
def AES_encrypt(msg_bytes, aeskey, aesiv):
    mode = AES.MODE_CBC
    msg_bytes = pad_to_num(16, msg_bytes)
    cryptos = AES.new(aeskey, mode, aesiv)
    cipher_msg = cryptos.encrypt(msg_bytes)
    return cipher_msg


# pad the msg utill the length of msg is num
def pad_to_num(num, msg_bytes):
    if len(msg_bytes) % num:
        add = num - (len(msg_bytes) % num)
    else:
        add = 0
    pad_hex = '00'
    pad_byte = bytes.fromhex(pad_hex)
    pad_msg = msg_bytes + (pad_byte * add)
    return pad_msg


# type:bytes
def AES_decrypt(cipher_msg, aeskey, aesiv):
    mode = AES.MODE_CBC
    cryptos = AES.new(aeskey, mode, aesiv)
    plain_text = cryptos.decrypt(cipher_msg)
    pad_hex = '20'
    pad_byte = bytes.fromhex(pad_hex)
    return plain_text.rstrip(pad_byte)


# generate a not zero-leading bytes,len is the bytes number
def gen_nonzeroleading_bytes(len):
    while True:
        rand_bytes = get_random_bytes(len)
        if rand_bytes[0] != 0:
            break
    return rand_bytes


def get_nozeroleading_hex(hexstr):
    if hexstr[0] == '0':
        hexstr = hexstr[1:]
    return hexstr


def sha256_hash(msg_bytes):
    return hashlib.sha256(msg_bytes).digest()


def double_sha256(msg_bytes):
    hash_digest = hashlib.sha256(hashlib.sha256(msg_bytes).digest()).digest()
    return hash_digest


# sk_bytes is bytes type to create Seckey class's object
# secret_msg is bytes of secret msg
# sig_ret is the der encode signature
def hash_sign(sk_bytes, tosign_data, secret_msg):
    hash_once_data = hashlib.sha256(tosign_data).digest()
    formal_sk = Seckey(sk_bytes)
    #sig_ret = formal_sk.sign(tosign_data, secret_msg)
    sig_ret = formal_sk.sign(hash_once_data, secret_msg)
    return sig_ret


# use ecdsa library to sign
def hash_sign2(sk, tosign_data, secretmsg_bytes):
    digest = double_sha256(tosign_data)
    k_int = int.from_bytes(secretmsg_bytes, "big")
    sig_ret = sk.sign_digest(digest, sigencode=util.sigencode_der, k=k_int)
    return sig_ret


def hash_sign3(sk, digest, secretmsg_bytes):
    k_int = int.from_bytes(secretmsg_bytes, "big")
    r, s = sk.sign_digest_eth(digest, sigencode=util.sigencode_der, k=k_int)
    return r,s


def verifysign_recover(sig, sk_bytes, tosign_data):
    hash_once_data = hashlib.sha256(tosign_data).digest()
    formal_sk = Seckey(sk_bytes)
    verify_ret, secret_msg = formal_sk.verify(hash_once_data, sig)
    return verify_ret, secret_msg


# ecdsa library
# sig is der-encoded type
# ret_verify is bool type
# k_recover is integer type
def verifysign_recover2(r,s, sk_bytes, pk_bytes, hash_digest):
    sk = recover_sk_fromstr(sk_bytes)
    pk = recover_pk_fromstr(pk_bytes)
    # hash_digest = double_sha256(msg_bytes)
    sig = util.sigencode_der(r, s, sk.privkey.order)

    ret_verify, k_recover = pk.verify_digest_recover(sig, hash_digest, sk, sigdecode=util.sigdecode_der)
    return ret_verify, k_recover


def AES_CTR_encrypt(msg_bytes, aeskey, aesiv):
    mode = AES.MODE_CTR
    cnt = int.to_bytes(1, 1, "big")
    cnt=Counter.new(128, initial_value=bytes_to_long(aesiv))
    cryptos = AES.new(aeskey, mode, counter=cnt)
    cipher_bytes = cryptos.encrypt(msg_bytes)
    return cipher_bytes


def AES_CTR_decrypt(msg_bytes, aeskey, aesiv):
    mode = AES.MODE_CTR
    cnt = int.to_bytes(1,1,"big")
    cnt = Counter.new(128, initial_value=bytes_to_long(aesiv))
    cryptos = AES.new(aeskey, mode, counter=cnt)
    plain_bytes = cryptos.decrypt(msg_bytes)
    return plain_bytes


def get_aeskey(dbname, btcaddr, ltcaddr):
    btc_skb = DB_select.get_skb_byDHaddr(dbname, 'bitcoin', btcaddr)
    ltc_skb = DB_select.get_skb_byDHaddr(dbname, 'litecoin', ltcaddr)
    msg_byte = btc_skb+ltc_skb
    hash_ret = sha256_hash(msg_byte)
    aeskey = hash_ret[:16]
    return aeskey


def receive_get_aeskey(dbname, btc_DHaddr, ltc_DHaddr):
    btc_skb = DB_select.receiver_get_DHskb(dbname,'bitcoin',btc_DHaddr)
    ltc_skb = DB_select.receiver_get_DHskb(dbname, 'litecoin', ltc_DHaddr)
    msg_byte = btc_skb+ltc_skb
    hash_ret = sha256_hash(msg_byte)
    aeskey = hash_ret[:16]
    return aeskey


# ————————————————同步模块——————————————————
def gen_selfaddr(nettype, coinname, db_name):
    sk, pk = gen_keypair()
    pk_b, sk_b = get_byteskeypair(pk, sk)
    addr = gen_address(pk, nettype, coinname)
    if coinname == 'bitcoin':
        DB_insert.self_addr_insert(sk_b, pk_b, addr, coinname, db_name)
    elif coinname == 'litecoin':
        DB_insert.self_addr_insert(sk_b, pk_b, addr, coinname, db_name)
    return addr


# ------reciever-------
# generate a address whose pkhash will have num_zero 0 after sha256hash
def gen_special_addr(num_zero, nettype, coinname, db_name):
    time_start = time.time()
    while True:
        sk, pk = gen_keypair()
        if coinname == 'bitcoin':
            pkhash = get_btc_pkhash(pk, nettype)
        elif coinname == 'litecoin':
            pkhash = get_ltc_pkhash(pk, nettype)
        tohash = pkhash
        hash_ret = hashlib.sha256(tohash).digest()
        hash_hex = hash_ret.hex()
        if hash_hex[:num_zero] == '0' * num_zero:
            pk_b, sk_b = get_byteskeypair(pk, sk)
            address = base58.b58encode(pkhash)
            if not DB_select.check_msg_receiver_addr(sk_b, coinname, db_name):
                DB_insert.msg_receiver_insert(sk_b, pk_b, address, coinname, db_name)
            break
    time_end = time.time()
    # print("run time:", time_end - time_start)
    return address.decode("utf-8")


def gen_special_ethaddr(num_zero, username):
    dbname = username+'.db'
    while True:
        sk, pk = gen_keypair()
        sk_hexstr = get_skbytes(sk).hex()
        sk_bytes = get_skbytes(sk)
        pk_bytes = get_uncompressed_pkbytes(pk)
        pk_hex = pk_bytes.hex()
        pk_hash = sha256_hash(pk_bytes).hex()
        if pk_hash[:num_zero] == '0'*num_zero:
            address_raw = '0x' + get_eth_address(pk).hex()
            address = ether_client.to_checksum_address(address_raw)
            if not DB_select.check_eth_receiver_addr(sk_bytes, dbname):
                DB_insert.receiver_eth_insert(sk_bytes, pk_bytes, address, dbname)
                ether_client.eth_importaddress(sk_hexstr, username)
            break
    return address


def computing_DHaddr(pk_A, skbyte_B, nettype, coinname):
    pk_point_A = pk_A.pubkey.point
    skbyteA_int = int.from_bytes(skbyte_B, "big")
    shared_point = skbyteA_int * pk_point_A
    shared_key = shared_point.x()  # int type

    shared_key_byte = int.to_bytes(shared_key, 32, "big")
    shared_skbytes = sha256_hash(shared_key_byte)
    shared_pk = get_pk_from_skbytes(shared_skbytes)
    shared_address = gen_address(shared_pk, nettype, coinname)
    return shared_address, shared_skbytes


def computing_eth_DHaddr(pk_A, skbyte_B):
    pk_point_A = pk_A.pubkey.point
    skbyteA_int = int.from_bytes(skbyte_B, "big")
    shared_point = skbyteA_int * pk_point_A
    shared_key = shared_point.x()  # int type

    shared_key_byte = int.to_bytes(shared_key, 32, "big")
    shared_skbytes = sha256_hash(shared_key_byte)
    shared_pk = get_pk_from_skbytes(shared_skbytes)
    shared_address_raw = get_eth_address(shared_pk)
    shared_address = ether_client.to_checksum_address(shared_address_raw)
    return shared_address, shared_skbytes


# -------sender--------
def gen_sender_addr(nettype,coinname):
    sk, pk = gen_keypair()
    sender_addr = gen_address(pk, nettype, coinname)
    pk_b, sk_b = get_byteskeypair(pk, sk)
    DB_insert.msg_sender_insert(sk_b, pk_b, sender_addr, coinname)
    return sender_addr


def DH_btc_sendaddress(dbname, skbyte_A, pk_B, nettype):
    pk_point_B = pk_B.pubkey.point
    skbyteA_int = int.from_bytes(skbyte_A, "big")
    shared_point = skbyteA_int * pk_point_B
    shared_key = shared_point.x()  # int type

    shared_key_byte = int.to_bytes(shared_key, 32, "big")
    shared_skbytes = sha256_hash(shared_key_byte)
    shared_pk = get_pk_from_skbytes(shared_skbytes)
    shared_address = gen_address(shared_pk, nettype, 'bitcoin')

    shared_pkbytes= shared_pk.to_string("compressed")
    shared_pk_script = get_btc_pkscript(shared_pk, nettype)
    find = DB_select.check_DH_pkscript(dbname, shared_pk_script, 'bitcoin')
    if not find:
        DB_insert.DH_addr_insert(dbname, shared_pk_script, shared_pkbytes, shared_skbytes, shared_address, 'bitcoin')
    return shared_address


def DH_ltc_sendaddress(dbname, skbyte_A, pk_B, nettype):
    pk_point_B = pk_B.pubkey.point
    skbyteA_int = int.from_bytes(skbyte_A, "big")
    shared_point = skbyteA_int * pk_point_B
    shared_key = shared_point.x()  # int type

    shared_key_byte = int.to_bytes(shared_key, 32, "big")
    shared_skbytes = sha256_hash(shared_key_byte)
    shared_pk = get_pk_from_skbytes(shared_skbytes)
    shared_address = gen_address(shared_pk, nettype, 'litecoin')

    shared_pkbytes= shared_pk.to_string("compressed")
    shared_pk_script = get_ltc_pkscript(shared_pk, nettype)
    find = DB_select.check_DH_pkscript(dbname, shared_pk_script, 'litecoin')
    if not find:
        DB_insert.DH_addr_insert(dbname, shared_pk_script, shared_pkbytes, shared_skbytes, shared_address, 'litecoin')
    return shared_address


def DH_eth_rawsendaddress(dbname, skbyte_A, pk_B):
    pk_point_B = pk_B.pubkey.point
    skbyteA_int = int.from_bytes(skbyte_A, "big")
    shared_point = skbyteA_int * pk_point_B
    shared_key = shared_point.x()  # int type

    shared_key_byte = int.to_bytes(shared_key, 32, "big")
    shared_skbytes = sha256_hash(shared_key_byte)
    shared_skhex = shared_skbytes.hex()
    shared_pk = get_pk_from_skbytes(shared_skbytes)
    shared_pkbytes = get_uncompressed_pkbytes(shared_pk)
    shared_address_raw = get_eth_address(shared_pk)
    shared_address = ether_client.to_checksum_address(shared_address_raw)
    print("eth_DHaddr:", shared_address)
    find = DB_select.sender_get_eth_DHaddr(dbname,shared_address,shared_skbytes)
    if not find:
        DB_insert.eth_DHaddr_insert(dbname, shared_skbytes, shared_pkbytes, shared_address)
    return shared_address_raw, shared_skhex

'''
# CFB will leak the feature of plaintext
def AES_CFB_encrypt(msg_bytes, aeskey, aesiv, length):
    mode = AES.MODE_CFB
    cipher_msg = b''
    block_num = int(length / 16)
    for i in range(block_num):
        cryptos = AES.new(aeskey, mode, aesiv,segment_size=128)
        cipher_msg += cryptos.encrypt(msg_bytes[:16])
        msg_bytes = msg_bytes[16:]
    cryptos = AES.new(aeskey, mode, aesiv, segment_size=128)
    cipher_msg += cryptos.encrypt(msg_bytes)
    return cipher_msg
'''

'''
def AES_CFB_decrypt(cipher_bytes, aeskey, aesiv, length):
    mode = AES.MODE_CFB
    plain_text = b''
    block_num = int(length/16)
    for i in range(block_num):
        cryptos = AES.new(aeskey, mode, aesiv,segment_size=128)
        plain_text += cryptos.decrypt(cipher_bytes[:16])
        cipher_bytes = cipher_bytes[16:]
    cryptos = AES.new(aeskey, mode, aesiv, segment_size=128)
    plain_text += cryptos.decrypt(cipher_bytes)
    return plain_text
'''


if __name__ == '__main__':
    '''
    pk_hex = "0361dd506c3dcc2e580c809518efd7d31cb2b22fa972fa84f6625e61b0e0ea6ed7"
    pk_raw = recover_pk_fromstr(bytes.fromhex(pk_hex))
    print("pkraw: ", pk_raw)
    #pkhash = get_btc_pkhash(pk_raw, "regtest")
    #ret = hashlib.sha256(pkhash).digest()
    #print(ret.hex())
    pk_byte = pk_raw.to_string()
    pk_byte2 = pk_raw.to_string("compressed")
    pk_byte3 = pk_raw.to_string("uncompressed")
    pk_byte4 = pk_raw.to_string("raw")
    pk_raw2 = recover_pk_fromstr(pk_byte2)
    print("pkraw2:", pk_raw2)
    '''
    '''
    d1 = pyDH.DiffieHellman()
    d2 = pyDH.DiffieHellman()
    d1_pubkey = d1.gen_public_key()
    d2_pubkey = d2.gen_public_key()
    d1_sharedkey = d1.gen_shared_key(d2_pubkey)
    d2_sharedkey = d2.gen_shared_key(d1_pubkey)
    d1_sharedkey == d2_sharedkey
    #print(type(d1_sharedkey))
    # sharedkey is a hex str
    sharedkey = bytes.fromhex(d1_sharedkey)
    B_sk, B_pk = gen_keypair()
    addr_B = gen_address(B_pk, 'regtest', 'bitcoin')
    pkhash_B = recover_btc_pkhash(addr_B)
    time_start = time.time()
    while True:
        sk, pk = gen_keypair()
        pkhash = get_btc_pkhash(pk, "testnet")
        tohash = pkhash + pkhash_B + sharedkey
        hash_ret = hashlib.sha256(tohash).digest()
        hash_hex = hash_ret.hex()
        #print("hash_hex:", hash_hex)
        if hash_hex[:2] == '0'*2:
            break
    print("find:", hash_hex)
    time_end = time.time()
    print("run time:", time_end - time_start)
    address = base58.b58encode(hash_ret)
    print("address:", address.decode("utf-8"))
    #address = "mmgd7NMyABKQF24ME74whCMotuCG59ivU2"

    pkhash = recover_btc_pkhash(address)
    print(pkhash.hex())

    for i in range(3, 6):
        print(i)
    '''

    '''
    sk_A, pk_A = gen_keypair()
    pk_point_A = pk_A.pubkey.point
    sk_B, pk_B = gen_keypair()
    pk_point_B = pk_B.pubkey.point

    skbyte_A = get_skbytes(sk_A)
    skbyteA_int = int.from_bytes(skbyte_A, "big")
    skbyte_B = get_skbytes(sk_B)
    skbyteB_int = int.from_bytes(skbyte_B, "big")
    retA = (skbyteA_int*pk_point_B).x()
    retB = (skbyteB_int*pk_point_A).x()
    print("retA:", type(retA))
    print("retB:", retB)
    '''
