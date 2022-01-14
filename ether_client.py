import decimal
import json
import random
import time

from eth_account import Account
from web3 import Web3
import eth_rlp
from eth_rlp import HashableRLP
#from coincurve import PublicKey as CCPublicKey
from eth_account._utils.signing import to_standard_v
from eth_account._utils.transactions import serializable_unsigned_transaction_from_dict
from eth_account._utils.transactions import encode_transaction
from eth_keys.datatypes import Signature
#from utils import Web3

import DB_insert
import DB_select
import crypto
import requests

import transaction

web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
ETHERSCAN_API_KEY = "4TE4G6ACFYS21ZAHY7SRKE74DG1JRP2IDE"


def eth_isvalid_addr(addr):
    return web3.isAddress(addr)


# get a send address
def eth_gen_selfaddress(username):
    sk, pk = crypto.gen_keypair()
    sk_hexstr = crypto.get_skbytes(sk).hex()
    # the second parameter is account's password
    sk_bytes = crypto.get_skbytes(sk)
    pk_bytes = crypto.get_uncompressed_pkbytes(pk)
    address = web3.geth.personal.importRawKey(sk_hexstr, username)
    dbname = username+'.db'
    DB_insert.self_ethaddr_insert(sk_bytes, pk_bytes, address, dbname)
    return address


def eth_gen_specialaddr(num_zero):
    while True:
        sk, pk = crypto.gen_keypair()
        sk_hexstr = crypto.get_skbytes(sk).hex()
        sk_bytes = crypto.get_skbytes(sk)
        pk_bytes = crypto.get_uncompressed_pkbytes(pk)
        pk_hex = pk_bytes.hex()
        self_address_raw = '0x'+crypto.get_eth_address(pk).hex()
        self_address = to_checksum_address(self_address_raw)
        hash_ret = crypto.sha256_hash(bytes.fromhex(self_address[2:])).hex()
        print(hash_ret)
        if hash_ret[:num_zero] == '0'*num_zero:
            print("find:", hash_ret)
            break
    return self_address


# privkey is hex type
def eth_importaddress(privkey, username):
    address = web3.geth.personal.importRawKey(privkey, username)
    checksum_address = to_checksum_address(address)
    return checksum_address


# raw_addr is hexstr with prefix '0x'
def to_checksum_address(raw_addr):
    return web3.toChecksumAddress(raw_addr)


def list_user_addr(username):
    all_accounts = web3.eth.accounts
    av_dict = dict()
    ret = None
    for addr in all_accounts:
        try:
           ret = web3.geth.personal.unlockAccount(addr, username)
           if ret:
                balance = eth_getbalance(addr)
                tmp_value = web3.fromWei(balance, "ether")
                av_dict[addr] = format(tmp_value, '.3f')
        except:
                pass
    return av_dict


def eth_sendtransaction(username, fromaddress, gas_price, gas_limit, to_raw_bytes, value):
    web3.geth.personal.unlockAccount(fromaddress, username)
    gas = '0x' + crypto.get_nozeroleading_hex(gas_limit.hex())
    gasprice = '0x' + crypto.get_nozeroleading_hex(gas_price.hex())
    to_raw_hex = '0x' + crypto.get_nozeroleading_hex(to_raw_bytes.hex())
    # to is a valid eth address of hex string type
    to = to_checksum_address(to_raw_hex)
    value = int.from_bytes(value, "big")
    print("gas:", gas)
    print("gasprice:", gasprice)
    print("to:", to)
    print("value:", value)
    txid_bytes = web3.eth.sendTransaction({'from': fromaddress, 'to': to, 'value': value, 'gas': gas, 'gasprice': gasprice})
    return txid_bytes.hex()


def eth_getbalance(address):
    #  the result is in wei type(10^18)
    balance = web3.eth.getBalance(address)
    # balance_wei = web3.fromWei(balance, "ether")
    return balance


def eth_get_txdetail(txid):
    tx_dict = web3.eth.getTransaction(txid)
    return tx_dict


def eth_minning(address):
    web3.geth.miner.setEtherbase(address)
    web3.geth.miner.start()
    time.sleep(3)
    web3.geth.miner.stop()


def eth_getblocknum():
    blocknum = web3.eth.blockNumber
    return blocknum


def get_sender_txid(fromaddr, since_blocknum):
    txid_list = list()
    blocknum_now = eth_getblocknum()
    #blocknum = since_blocknum
    for i in range(since_blocknum, blocknum_now+1):
        block = web3.eth.getBlock(i, True)
        tx_list = block['transactions']
        if len(tx_list):
            for j in range(len(tx_list)):
                if tx_list[j]['from'] == fromaddr:
                    txid_list.append(tx_list[j]['hash'].hex())
        #blocknum += 1
    return txid_list


def get_all_txid(blocksince):
    txid_list = list()
    block_now = eth_getblocknum()
    for i in range(blocksince,block_now+1):
        block = web3.eth.getBlock(i, True)
        tx_list = block['transactions']
        if tx_list:
            for j in range(len(tx_list)):
                txid_list.append(tx_list[j]['hash'].hex())
    return txid_list


# return type is pk_bytes
def recover_pk_fromsig(txid):
    tx_dict = eth_get_txdetail(txid)
    v = tx_dict['v']
    r = tx_dict['r']
    s = tx_dict['s']
    vrs = (to_standard_v(v),
           int.from_bytes(r, 'big'),
           int.from_bytes(s, 'big'))
    signature = Signature(vrs=vrs)
    tx_json = {
        'nonce': tx_dict['nonce'],
        'gasPrice': tx_dict['gasPrice'],
        'gas': tx_dict['gas'],
        'to': tx_dict['to'],
        'value': tx_dict['value']
    }
    tx_json['chainId'] = "0x0f"
    tx_json['data'] = '0x'
    serialized_tx = serializable_unsigned_transaction_from_dict(tx_json)
    rec_pub = signature.recover_public_key_from_msg_hash(serialized_tx.hash())  # pk_raw类型
    pk_bytes = rec_pub._raw_key
    pk = crypto.recover_pk_fromstr(pk_bytes)
    return pk_bytes


def find_special_pk(num_zero, blocksince):
    blocknum_now = eth_getblocknum()
    pk_list=list()
    for i in range(blocksince, blocknum_now + 1):
        block = web3.eth.getBlock(i, True)
        tx_list = block['transactions']
        if len(tx_list):
            for j in range(len(tx_list)):
                tx= tx_list[j]
                txid=tx['hash'].hex()
                #print("txid:",txid)
                pk_bytes = bytes.fromhex('04')+recover_pk_fromsig(txid)
                #print("pk_b:", pk_bytes.hex())
                pk_hash = crypto.sha256_hash(pk_bytes).hex()
                if pk_hash[:num_zero] == '0' * num_zero:
                    pk_list.append(pk_bytes)
                    break
            if len(pk_list):
                break
    return pk_list


def eth_sendrawtx(dbname, fromaddr, Eth_txmsg):
    '''
    sk,pk = crypto.gen_keypair()
    #fromaddr = to_checksum_address(crypto.get_eth_address(pk))
    sk_hex = crypto.get_skbytes(sk).hex()
    fromaddr = eth_importaddress(sk_hex, "")
    print("addr:",fromaddr)
    print("sk_hex:", sk_hex)
    #eth_minning(fromaddr)
    '''
    #skb = DB_select.sender_get_ethDHskb(dbname, fromaddr)
    skb = DB_select.get_user_ethskb(dbname, fromaddr)
    print("skb", skb.hex())
    sk = crypto.recover_sk_fromstr(skb)
    hashid = int.from_bytes(Eth_txmsg.to_msg, "big")
    to_raw_bytes = DB_select.get_toaddr_by_ethtargetaddr(hashid)
    to = to_checksum_address(to_raw_bytes)
    nonce = web3.eth.getTransactionCount(fromaddr, "pending")
    #nonce = "null"
    value_byte = crypto.gen_nonzeroleading_bytes(1) + Eth_txmsg.value_msg
    value = int.from_bytes(value_byte, "big")
    print("eth_value: ", value)
    txn_dict = {
        'to': to,
        'value': web3.toWei(0.0000001, 'ether'),  # wei
        #'gasPrice': web3.toWei(20, 'gwei'),
        'gasPrice': web3.toWei(1, 'gwei'),
        'nonce': nonce,
        'chainId': 15,
        'gas': 21000,
        'data': '0x',
    }
    #txn_dict['gas'] = web3.eth.estimateGas(txn_dict)
    serial_data = serializable_unsigned_transaction_from_dict(txn_dict)
    tosign_digest = serial_data.hash()
    secretmsg_bytes = int.to_bytes(random.randint(1, 255), 1, "big") + Eth_txmsg.sig_msg
    r, s = crypto.hash_sign3(sk, tosign_digest, secretmsg_bytes)
    chainID = 15
    v = 2*chainID+35  # 表示偶数的临时公钥值（以便恢复公钥时的操作）
    #print("r:", r)
    #print("s:", s)
    txn_dict['v']=v
    txn_dict['r']=r
    txn_dict['s']=s

    vrs=(v,r,s)
    raw_tx=encode_transaction(serial_data, vrs)
    print("raw_tx:", raw_tx.hex())
    #signed_txn = web3.eth.account.signTransaction(txn_dict, acct.key)
    try:
        txid = web3.eth.sendRawTransaction(raw_tx)
        print("txid:",txid.hex())
        return txid.hex()
    except Exception as e:
        raise Exception("error:", e)


def recover_msg(dbname, fromaddr, txid):
    tx = eth_get_txdetail(txid)
    to = tx['to']
    value = tx['value']
    gas = tx['gas']
    gasprice = tx['gasPrice']
    chainID = 15
    nonce = tx['nonce']
    r = tx['r']
    s = tx['s']
    int_r = int.from_bytes(r, "big")
    int_s = int.from_bytes(s, "big")
    txn_dict = {
        'to': to,
        'value': value,
        'gasPrice': gasprice,
        'nonce': nonce,
        'chainId': 15,
        'gas': gas,
        'data': '0x',
    }
    serial_data = serializable_unsigned_transaction_from_dict(txn_dict)
    tosign_digest = serial_data.hash()
    pkbytes = recover_pk_fromsig(txid)
    skb = DB_select.receiver_get_ethDHskb(dbname, fromaddr)
    verify_flag, k_int = crypto.verifysign_recover2(int_r, int_s, skb, pkbytes, tosign_digest)
    return verify_flag, k_int

def ui_transfer_ether(username, from_address, to_address, value):
    #value_dm = decimal.Decimal(value)
    #value_wei = value_dm*1000000000000000000
    value = web3.toWei(value, "ether")
    print(type(value))
    balance = eth_getbalance(from_address)
    #print(type(balance))
    if value < balance:
        #value = web3.toWei(value, "ether")#value必须是number或者string类型
        #print(value)
        web3.geth.personal.unlockAccount(from_address, username)
        tranhash= web3.eth.sendTransaction({'from': from_address, 'to': to_address, 'value': value, 'gas': 50000})
        finalhash = tranhash.hex()
        #web3.geth.miner.start()
        #time.sleep(2)
        #web3.geth.miner.stop()
        return finalhash
    else:
        errorinfo="send failed"
        return errorinfo


# used in mainnet
def get_last_txs(address, since=2):
    return json.loads(requests.get(
        f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock={since}&sort=asc&apikey={ETHERSCAN_API_KEY}"
    ).text)["result"]


if __name__ == '__main__':

    '''
    mining_addr = "0xbe4b937fec235dd17f0750309dbf0dc013aa942b"
    check_addr = to_checksum_address(mining_addr)
    addr = "0xcb6a857e4bfbc68a4ee20e92048d81af128e9361"
    che_addr = to_checksum_address(addr)
    print(eth_getbalance(che_addr))
    #print(get_sender_txid(check_addr, 5))
    '''
    '''
    tx_list = block['transactions']  # there may be several transactions
    txid_list = list()
    if len(tx_list):
        for i in range(len(tx_list)):
            txid = tx_list[i]['hash']
            txid_list.append(txid)
    print((txid_list[0].hex()))
    '''
    #(eth_getbalance(addr))
    #eth_minning(mining_addr)
    #addr = web3.eth.accounts[1]
    #block = web3.eth.getBlock(310, True)
    #ret = block.transactions
    #print(ret)
    #print((ret[0]['hash'].hex()))
    #print(web3.eth.blockNumber)
    #txid_list = get_sender_txid(addr,0)
    #print(txid_list)

    '''
    fromaddress = "0x2F42a6EDf066bb98770Ea61202B2a1942A5A65ac"
    to = "0x9Cc0c2eBED26336c036DD73c2D160f18Bc7e3D7f"
    web3.geth.personal.unlockAccount(fromaddress, "")
    txid = web3.eth.sendTransaction({'from': fromaddress, 'to':to, 'value': 13632, 'gas': "0x21000", 'gasprice': "0x172d234523"})
    print(txid)
    '''
    #addr = eth_getnewaddress("Alice")
    #selfaddress = eth_createaddr("")
    #print("selfaddr:",selfaddress)

    # 从交易单中的签名恢复公钥


    '''
    tx_dict = eth_get_txdetail(txid)
    v = tx_dict['v']
    r = tx_dict['r']
    s = tx_dict['s']
    vrs = (to_standard_v(v),
           int.from_bytes(r, 'big'),
           int.from_bytes(s, 'big'))
    signature = Signature(vrs=vrs)
    tx_json = {
        'nonce': tx_dict['nonce'],
        'gasPrice': tx_dict['gasPrice'],
        'gas': tx_dict['gas'],
        'to': tx_dict['to'],
        'value': tx_dict['value']
    }
    tx_json['chainId'] = "0x0f"
    tx_json['data'] = '0x'
    serialized_tx = serializable_unsigned_transaction_from_dict(tx_json)
    rec_pub = signature.recover_public_key_from_msg_hash(serialized_tx.hash())
    
    print("raw_addr:",tx_dict['from'])
    #print("recover_addr:",rec_pub.to_checksum_address())
    '''


    '''
    addr = "0x9B66661db7B65792f4cFb0C7114C001Ba974e9A6"
    eth_sendrawtx(addr)
    # print(eth_get_txdetail("0x3eae0ec242cf5ff6b261740880f2f7a5802feadeda42a1e6ebd175bd0fae0942"))
    flag, k = recover_msg("0x3eae0ec242cf5ff6b261740880f2f7a5802feadeda42a1e6ebd175bd0fae0942")
    print(flag, k)
    print(int.to_bytes(k, 32, "big").decode("utf-8"))
    '''
    eth_addr = "0x3aae77d65687f18eE8E255Cf5F8F07Ad9963F803"
    tx_slice = crypto.get_random_bytes(14)
    eth_txmsg = transaction.prepare_ethtx_data2(tx_slice)
    eth_sendrawtx('Alice.db', eth_addr, eth_txmsg)