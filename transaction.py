import re
import sys
from collections import namedtuple
from ecdsa import util

from Crypto.Random import get_random_bytes

import bitcoin_client
import crypto
import DB_select
import random

import ether_client
import litecoin_client
import serialize

VERSION = 1
LOCKTIME = 0
PRICE_PER_BYTE = 10

# txid is a hexstring
# vout is integer
Outpoint = namedtuple('Outpoint', ['txid', 'vout'])

# sequence_msg,value_msg except nulldata are all list type
# every sequence:4 bytes, value:2 bytes, addr:2 bytes, sig:31 bytes, nulldata:40 bytes
Tx_msg = namedtuple('Tx_msg', ['sequence_msg', 'value_msg', 'addr_msg', 'sig_msg', 'nulldata'])


# preout is Outpoint type
# sequence is bytes type
# script_sig is already serialized including OP_PUSHDATA1 and <sigdata+0x01><raw_pubkey>
# script_size is integer in Tx_in, it will be varint type after serializing
Tx_in = namedtuple('Tx_in', ['preout', 'script_size', 'script_sig', 'sequence'])

# value is integer
# script_pubkey is serialized including OP code,not the 20 bytes pk_script
# script_size type is the same as above in Tx_in
Tx_out = namedtuple('Tx_out', ['value', 'script_size', 'script_pubkey'])

# version is integer, txin_list is the list of txin, txout_list is the same
Tx = namedtuple('Tx', ['version', 'txin_list', 'txout_list', 'locktime'])

Eth_Txmsg = namedtuple('Eth_Txmsg', ['gas_price_msg', 'gas_limit_msg', 'to_msg', 'value_msg'])

Eth_Txmsg2 = namedtuple('Eth_Txmsg', ['to_msg', 'value_msg', 'sig_msg'])

def prepare_btctx_data(msg_padded, in_num, out_num):
    # Tx_msg = namedtuple('Tx_msg', ['sequence_msg', 'value_msg', 'addr_msg', 'sig_msg', 'nulldata'])
    sequence_msg = list()
    value_msg = list()
    addr_msg = list()
    sig_msg = list()
    for i in range(in_num):
        sequence = msg_padded[:4]
        sequence_msg.append(sequence)
        msg_padded = msg_padded[4:]
    for i in range(out_num):
        value = msg_padded[:2]
        value_msg.append(value)
        msg_padded = msg_padded[2:]
    for i in range(out_num):
        addr = msg_padded[:2]
        addr_msg.append(addr)
        msg_padded = msg_padded[2:]
    for i in range(in_num):
        sig = msg_padded[:31]
        sig_msg.append(sig)
        msg_padded = msg_padded[31:]
    nulldata = msg_padded[:40]
    tx_msg = Tx_msg(sequence_msg, value_msg, addr_msg, sig_msg, nulldata)
    return tx_msg


# msg_padded: the msg padded to a tx capacity, type is bytes
# oplist_in: the list of Outpoint(txid,vout_index) as the vin of tx
# unspent_value: the unspent money of the sending address, here is satoshi
# nulldata is a txout whose script_pubkey is different from others
def btc_create_tx(dbname, msg_padded, oplist_in, out_num, sender_pkscript, unspent_value):
    tx_msg = prepare_btctx_data(msg_padded, len(oplist_in), out_num)
    txin_list = list()
    txout_list = list()

    for i in range(len(oplist_in)):
        preout = oplist_in[i]
        script_size = None  # set a empty value for script_size to create txin
        script_sig = None
        sequence = tx_msg.sequence_msg[i]
        txin = Tx_in(preout, script_size, script_sig, sequence)
        txin_list.append(txin)

    for i in range(out_num):
        hashid_bytes = tx_msg.addr_msg[i]
        hashid_int = int.from_bytes(hashid_bytes, "big")
        reciver_pkscript = DB_select.get_pkscript_by_targetaddr(hashid_int, 'bitcoin')  # the pk_script of the out(reciever)
        script_pk = serialize.tobuf_pkscript(reciver_pkscript)
        script_size = len(script_pk)
        value_bytes = tx_msg.value_msg[i]
        value_int = int.from_bytes(value_bytes, "big")
        #print("value_int:", value_int)
        #print("unspent_value:", unspent_value)
        rg = int((unspent_value - 0x10000 - (out_num - i) * 0x20000 - 0x10000) / 0x10000)
        #value_final = int((random.randint(0, int((rg-1)/20)) % rg + 1)) * 0x10000 + value_int
        value_final = (random.randint(0, 8) + 1) * 0x10000 + value_int
        print("value_final:", value_final)
        txout = Tx_out(value_final, script_size, script_pk)
        txout_list.append(txout)
        if unspent_value < value_final:
            raise Exception("wrong balance")
        else:
            unspent_value = unspent_value - value_final
        # to contribute a txout for itself
    tx = Tx(VERSION, txin_list, txout_list, LOCKTIME)
    tx_buf = serialize.tobuf_tx(tx)
    print("txbuf:", tx_buf.hex())
    # fee = get_txfee(len(tx_buf)+len(tx.txin_list)*75+80)
    fee = get_txfee(len(tx_buf)+len(tx.txin_list)*112+80)
    if unspent_value < fee:
        raise Exception("can't afford the fee")
    else:
        self_value = unspent_value - fee
    print("fee:", fee)
    unspent_value = unspent_value - fee
    self_script_pk = serialize.tobuf_pkscript(sender_pkscript)
    self_script_size = len(self_script_pk)
    to_self = Tx_out(self_value, self_script_size, self_script_pk)
    tx.txout_list.append(to_self)

    nulldata_scriptpk = serialize.tobuf_nulldata(tx_msg.nulldata)
    nulldata_out = Tx_out(0, len(nulldata_scriptpk), nulldata_scriptpk)
    tx.txout_list.append(nulldata_out)


    # create signature for tx
    sk_b = DB_select.get_skbytes(dbname, sender_pkscript, 'bitcoin')
    sign_tx(dbname, tx, sk_b, sender_pkscript, tx_msg, 'bitcoin')
    return tx, unspent_value


def ltc_create_tx(dbname, msg_padded, oplist_in, out_num, sender_pkscript, unspent_value):
    tx_msg = prepare_btctx_data(msg_padded, len(oplist_in), out_num)
    txin_list = list()
    txout_list = list()

    for i in range(len(oplist_in)):
        preout = oplist_in[i]
        script_size = None  # set a empty value for script_size to create txin
        script_sig = None
        sequence = tx_msg.sequence_msg[i]
        txin = Tx_in(preout, script_size, script_sig, sequence)
        txin_list.append(txin)

    for i in range(out_num):
        hashid_bytes = tx_msg.addr_msg[i]
        hashid_int = int.from_bytes(hashid_bytes, "big")
        reciver_pkscript = DB_select.get_pkscript_by_targetaddr(hashid_int, 'litecoin')   # the pk_script of the out(reciever)
        script_pk = serialize.tobuf_pkscript(reciver_pkscript)
        script_size = len(script_pk)
        value_bytes = tx_msg.value_msg[i]
        value_int = int.from_bytes(value_bytes, "big")
        # print("value_int:", value_int)
        # print("unspent_value:", unspent_value)
        rg = int((unspent_value - 0x10000 - (out_num - i) * 0x20000 - 0x10000) / 0x10000)
        # value_final = int((random.randint(0, int((rg-1)/20)) % rg + 1)) * 0x10000 + value_int
        value_final = (random.randint(0, 8) + 1) * 0x10000 + value_int
        print("value_final:", value_final)
        txout = Tx_out(value_final, script_size, script_pk)
        txout_list.append(txout)
        if unspent_value < value_final:
            raise Exception("wrong balance")
        else:
            unspent_value = unspent_value - value_final
        # to contribute a txout for itself
    tx = Tx(VERSION, txin_list, txout_list, LOCKTIME)
    tx_buf = serialize.tobuf_tx(tx)
    fee = get_txfee(len(tx_buf) + len(tx.txin_list) * 75 + 80)
    if unspent_value < fee:
        raise Exception("can't afford the fee")
    else:
        self_value = unspent_value - fee
    print("fee:", fee)
    unspent_value = unspent_value - fee
    self_script_pk = serialize.tobuf_pkscript(sender_pkscript)
    self_script_size = len(self_script_pk)
    to_self = Tx_out(self_value, self_script_size, self_script_pk)
    tx.txout_list.append(to_self)

    nulldata_scriptpk = serialize.tobuf_nulldata(tx_msg.nulldata)
    nulldata_out = Tx_out(0, len(nulldata_scriptpk), nulldata_scriptpk)
    tx.txout_list.append(nulldata_out)

    # create signature for tx
    sk_b = DB_select.get_skbytes(dbname, sender_pkscript, 'litecoin')
    sign_tx(dbname, tx, sk_b, sender_pkscript, tx_msg, 'litecoin')
    return tx, unspent_value


def sign_tx(dbname, tx, sk_bytes, sender_pkscript, tx_msg, coinname):
    for i in range(len(tx.txin_list)):
        script_pk = serialize.tobuf_pkscript(sender_pkscript)
        tosign_data = tosign(tx, i, script_pk)
        #print("tosigndata:", tosign_data.hex())
        sig_msg = tx_msg.sig_msg[i]   # the size of tx_msg.sig_msg is just 31 bytes, signing needs 32 bytes integer
        print("hide_k_byte:", sig_msg.hex())
        sk = crypto.recover_sk_fromstr(sk_bytes)
        # sig = crypto.hash_sign(sk, tosign_data, sig_msg)
        sig = crypto.hash_sign(sk_bytes, tosign_data, sig_msg)
        sig = sig + int.to_bytes(1, 1, "big")  # HASHALL type 0x01
        if coinname == 'bitcoin':
            pk_bytes = DB_select.get_pkbytes(dbname, sender_pkscript, 'bitcoin')
        elif coinname == 'litecoin':
            pk_bytes = DB_select.get_pkbytes(dbname, sender_pkscript, 'litecoin')
        script_sig = serialize.tobuf_sigscript(sig, pk_bytes)
        tx.txin_list[i] = tx.txin_list[i]._replace(script_sig=script_sig)
        #print("sig = ", tx.txin_list[i].script_sig.hex())
        script_len = len(script_sig)
        tx.txin_list[i] = tx.txin_list[i]._replace(script_size=script_len)
    return tx


def ltc_sign_tx(tx, sk_bytes, sender_pkscript, tx_msg):
    for i in range(len(tx.txin_list)):
        script_pk = serialize.tobuf_pkscript(sender_pkscript)
        tosign_data = tosign(tx, i, script_pk)
        print("tosigndata:", tosign_data.hex())
        sig_msg = tx_msg.sig_msg[i]  # the size of tx_msg.sig_msg is just 31 bytes, signing needs 32 bytes integer
        sig = crypto.hash_sign(sk_bytes, tosign_data, sig_msg)
        sig = sig + int.to_bytes(1, 1, "big")  # HASHALL type 0x01
        pk_bytes = DB_select.get_pkbytes(sender_pkscript, 'litecoin')# get pk_bytes by enquiring database
        script_sig = serialize.tobuf_sigscript(sig, pk_bytes)
        tx.txin_list[i] = tx.txin_list[i]._replace(script_sig=script_sig)
        print("sig = ", tx.txin_list[i].script_sig.hex())
        script_len = len(script_sig)
        tx.txin_list[i] = tx.txin_list[i]._replace(script_size=script_len)
        print("sig len = ", tx.txin_list[i].script_size)
    return tx


def tosign(tx, in_num, script_pk):
    buf_bytes = int.to_bytes(tx.version, 4, "little")
    txin_cnt = len(tx.txin_list)
    txout_cnt = len(tx.txout_list)
    buf_bytes = buf_bytes + serialize.to_Varintbuf_size(txin_cnt)
    for i in range(txin_cnt):
        buf_bytes = buf_bytes + serialize.tobuf_outpoint(tx.txin_list[i].preout)
        if i == in_num:
            buf_bytes += serialize.to_Varintbuf_size(len(script_pk))
            buf_bytes += script_pk
        else:
            buf_bytes = buf_bytes + serialize.to_Varintbuf_size(0)
        seq = tx.txin_list[i].sequence
        buf_bytes += seq[::-1]
    buf_bytes += serialize.to_Varintbuf_size(txout_cnt)
    for i in range(txout_cnt):
        buf_bytes += serialize.tobuf_txout(tx.txout_list[i])
    buf_bytes += int.to_bytes(tx.locktime, 4, "little")
    buf_bytes += int.to_bytes(1, 4, "little") # Append hash-type(HASH_ALL) 0x01 of 32bit
    return buf_bytes


def get_txfee(bytecnt):
    fee = bytecnt * PRICE_PER_BYTE
    return fee


def btc_get_tx(addr, block_since):
    tx_list = list()
    txid_list = bitcoin_client.get_sender_txid(addr, block_since)
    print("txid_list:", txid_list)
    for i in range(len(txid_list)):
        txhex = bitcoin_client.btc_getrawtransaction2(txid_list[i])
        tx = serialize.parse_txbuf(txhex)
        tx_list.append(tx)
    return tx_list, txid_list


# get the first 4 Bytes to see if belongs to the session
def btc_get_rawmsg_header(tx):
    seq_msg = list()
    txin_cnt = len(tx.txin_list)
    txin_list = tx.txin_list
    for i in range(txin_cnt):
        sequence = txin_list[i].sequence
        seq_msg.append(sequence)
    # tx_msg = Tx_msg(seq_msg, value_msg, addr_msg, sig_msg, nulldata)
    raw_msg = b''
    for i in range(len(seq_msg)):
        raw_msg += seq_msg[i]
    return raw_msg


def btc_get_rawmsg(dbname, btcDHaddr, tx, sender_pkscript):
    sig_msg = list()
    seq_msg = list()
    value_msg = list()
    addr_msg = list()
    txin_cnt = len(tx.txin_list)
    txin_list = tx.txin_list
    txout_list = tx.txout_list
    script_pk = serialize.tobuf_pkscript(sender_pkscript)
    #sk_bytes = DB_select.get_skbytes(dbname, sender_pkscript, 'bitcoin')
    sk_bytes=DB_select.receiver_get_DHskb(dbname,'bitcoin',btcDHaddr)
    #pk_bytes = DB_select.get_pkbytes(dbname, sender_pkscript, 'bitcoin')
    for i in range(txin_cnt):
        sequence = txin_list[i].sequence
        seq_msg.append(sequence)
        sig = serialize.parse_scriptsig(txin_list[i].script_sig)
        tosign_data = tosign(tx, i, script_pk)
        verify_ret, recover_secretmsg = crypto.verifysign_recover(sig, sk_bytes, tosign_data)
        if not verify_ret:
            raise Exception("signature verify failed")
        else:
            print("recover_k_byte:", recover_secretmsg.hex())
        sig_msg.append(recover_secretmsg)
    txout_cnt = len(tx.txout_list)
    for i in range(txout_cnt - 2):
        value_hide = txout_list[i].value & 0xffff
        value_buf = int.to_bytes(value_hide, 2, "big")
        value_msg.append(value_buf)
        reciver_pkscript = serialize.parse_scriptpk(txout_list[i].script_pubkey)
        addr_hide = reciver_pkscript[:2]
        addr_msg.append(addr_hide)
    nulldata = serialize.parse_scriptpk(txout_list[txout_cnt - 1].script_pubkey)
    # tx_msg = Tx_msg(seq_msg, value_msg, addr_msg, sig_msg, nulldata)
    raw_msg = b''
    for i in range(len(seq_msg)):
        raw_msg += seq_msg[i]
    for i in range(len(value_msg)):
        raw_msg += value_msg[i]
    for i in range(len(addr_msg)):
        raw_msg += addr_msg[i]
    for i in range(len(sig_msg)):
        raw_msg += sig_msg[i]
    raw_msg += nulldata
    return raw_msg


def ltc_get_tx(addr, block_since):
    tx_list = list()
    txid_list = litecoin_client.get_sender_txid(addr, block_since)
    print("txid_list:", txid_list)
    for i in range(len(txid_list)):
        txhex = litecoin_client.ltc_getrawtransaction(txid_list[i])
        tx = serialize.parse_txbuf(txhex)
        tx_list.append(tx)
    return tx_list, txid_list


# get the first 4 Bytes to see if belongs to the session
def ltc_get_rawmsg_header(tx):
    seq_msg = list()
    txin_cnt = len(tx.txin_list)
    txin_list = tx.txin_list
    for i in range(txin_cnt):
        sequence = txin_list[i].sequence
        seq_msg.append(sequence)
    # tx_msg = Tx_msg(seq_msg, value_msg, addr_msg, sig_msg, nulldata)
    raw_msg = b''
    for i in range(len(seq_msg)):
        raw_msg += seq_msg[i]
    return raw_msg


def ltc_get_rawmsg(dbname, ltcDHaddr, tx, sender_pkscript):
    sig_msg = list()
    seq_msg = list()
    value_msg = list()
    addr_msg = list()
    txin_cnt = len(tx.txin_list)
    txin_list = tx.txin_list
    txout_list = tx.txout_list
    script_pk = serialize.tobuf_pkscript(sender_pkscript)
    sk_bytes = DB_select.receiver_get_DHskb(dbname, 'litecoin', ltcDHaddr)
    #pk_bytes = DB_select.get_pkbytes(dbname, sender_pkscript, 'litecoin')
    for i in range(txin_cnt):
        sequence = txin_list[i].sequence
        seq_msg.append(sequence)
        sig = serialize.parse_scriptsig(txin_list[i].script_sig)
        tosign_data = tosign(tx, i, script_pk)
        verify_ret, recover_secretmsg = crypto.verifysign_recover(sig, sk_bytes, tosign_data)
        if not verify_ret:
            raise Exception("signature verify failed")
        else:
            print("recover_k_byte:", recover_secretmsg.hex())
        sig_msg.append(recover_secretmsg)
    txout_cnt = len(tx.txout_list)
    for i in range(txout_cnt - 2):
        value_hide = txout_list[i].value & 0xffff
        value_buf = int.to_bytes(value_hide, 2, "big")
        value_msg.append(value_buf)
        reciver_pkscript = serialize.parse_scriptpk(txout_list[i].script_pubkey)
        addr_hide = reciver_pkscript[:2]
        addr_msg.append(addr_hide)
    nulldata = serialize.parse_scriptpk(txout_list[txout_cnt - 1].script_pubkey)
    # tx_msg = Tx_msg(seq_msg, value_msg, addr_msg, sig_msg, nulldata)
    raw_msg = b''
    for i in range(len(seq_msg)):
        raw_msg += seq_msg[i]
    for i in range(len(value_msg)):
        raw_msg += value_msg[i]
    for i in range(len(addr_msg)):
        raw_msg += addr_msg[i]
    for i in range(len(sig_msg)):
        raw_msg += sig_msg[i]
    raw_msg += nulldata
    return raw_msg


# every parameters in Eth_Txmsg is bytes type
# gas_price: 4B, gas_limit:2B, to:2B, value:6B
# gas_price total:5B
# gas_limit total:3B
# to :2B
# value total: 7~8B
def prepare_ethtx_data(msg_padded):
    #eth_tx = namedtuple('Eth_tx', ['gas_price', 'gas_limit', 'toaddr', 'value'])
    gas_price_msg = msg_padded[:4]
    msg_padded = msg_padded[4:]
    gas_limit_msg = msg_padded[:2]
    msg_padded = msg_padded[2:]
    #toaddress = DB_select.get_toaddr_by_ethtargetaddr(hashid)
    to_msg = msg_padded[:2]
    msg_padded = msg_padded[2:]
    value_msg = msg_padded[:6]
    eth_txmsg = Eth_Txmsg(gas_price_msg, gas_limit_msg, to_msg, value_msg)
    '''
    gas_price = crypto.gen_nonzeroleading_bytes(1) + eth_txmsg.gas_price_msg
    gas_limit = crypto.gen_nonzeroleading_bytes(1) + eth_txmsg.gas_limit_msg
    hashid = int.from_bytes(eth_txmsg.to_msg, "big")
    to_raw_bytes = DB_select.get_toaddr_by_ethtargetaddr(hashid)
    value = crypto.gen_nonzeroleading_bytes(random.randint(1, 2)) + eth_txmsg.value_msg
    eth_tx.gas_price = gas_price
    eth_tx.gas_limit = gas_limit
    eth_tx.toaddr = to_raw_bytes
    eth_tx.value = value
    '''
    return eth_txmsg


def prepare_ethtx_data2(msg_padded):
    #eth_tx = namedtuple('Eth_tx', ['gas_price', 'gas_limit', 'toaddr', 'value'])
    #toaddress = DB_select.get_toaddr_by_ethtargetaddr(hashid)
    to_msg = msg_padded[:2]
    msg_padded = msg_padded[2:]
    value_msg = msg_padded[:6]
    msg_padded = msg_padded[6:]
    sig_msg = msg_padded[:31]
    eth_txmsg = Eth_Txmsg2( to_msg, value_msg, sig_msg)
    return eth_txmsg

# gas_price total:5B
# gas_limit total:3B
# to :2B
# value total: 7~8B
def eth_send_tx(username, fromaddr, eth_txmsg):
    gas_price = crypto.gen_nonzeroleading_bytes(1) + eth_txmsg.gas_price_msg
    gas_limit = crypto.gen_nonzeroleading_bytes(1) + eth_txmsg.gas_limit_msg
    hashid = int.from_bytes(eth_txmsg.to_msg, "big")
    to_raw_bytes = DB_select.get_toaddr_by_ethtargetaddr(hashid)
    # value = crypto.gen_nonzeroleading_bytes(random.randint(1, 2)) + eth_txmsg.value_msg
    value = crypto.gen_nonzeroleading_bytes(1) + eth_txmsg.value_msg
    txid = ether_client.eth_sendtransaction(username, fromaddr, gas_price, gas_limit, to_raw_bytes, value)
    return txid


def eth_send_tx2(fromaddr, eth_tx):
    txid = ether_client.eth_sendtransaction(fromaddr, eth_tx.gas_price, eth_tx.gas_limit, eth_tx.toaddr, eth_tx.value)
    return txid


def eth_get_rawmsg(txid):
    tx_dict = ether_client.eth_get_txdetail(txid)
    gas_limit = int.to_bytes(tx_dict['gas'], 3, "big")
    gaslimit_msg = gas_limit[-2:]
    gas_price = int.to_bytes(tx_dict['gasPrice'], 5, "big")
    gasprice_msg = gas_price[-4:]
    to_msg_hex = tx_dict['to'][-4:]
    to_msg = bytes.fromhex(to_msg_hex)
    value = int.to_bytes(tx_dict['value'], 8, "big")
    value_msg = value[-6:]
    raw_msg = gasprice_msg + gaslimit_msg + to_msg + value_msg
    return raw_msg


def eth_get_rawmsg2(txid):
    tx_dict = ether_client.eth_get_txdetail(txid)
    to_msg_hex = tx_dict['to'][-4:]
    to_msg = bytes.fromhex(to_msg_hex)
    value = int.to_bytes(tx_dict['value'], 8, "big")
    value_msg = value[-6:]
    flag, k_int = ether_client.recover_msg(txid)
    if not flag:
        raise Exception("recover eth sig_msg failed!")
    else:
        sig_msg = int.to_bytes(k_int, 31, "big").decode("utf-8")
    raw_msg = to_msg + value_msg + sig_msg
    return raw_msg


if __name__ == '__main__':

    address = "muKJ7eShsa67pF4SVWSudGUyE9PmgbhTir"
    '''
    oplist, unspent_value = bitcoin_client.get_unspent(address)
    capacity = len(oplist)*35 + 3*4 + 40
    # = crypto.pad_to_num(capacity, msg)
    #msg_padded = b'12345'*17+b'12'
    msg_padded = bytes.fromhex("030000005c2ca8a3002bbd017c278acc0ab78ac44735a2c80874e4aa26949c2067dd50aa4713fa971da86ea6cab0d552ba5b057ae28e54eaf9ce79df285cc618fb0eb19de7d6993a11e59bfec9649d2155384bad78b5bc")
    print("befor_msg:", msg_padded.hex())
    sat_value = int(unspent_value * 100000000)
    #print("oplist:", oplist)
    #print(sat_value)
    if sat_value < 0x90000:
        print("insuffient balance")
    sender_pkscript = crypto.get_pkscript_by_addr(address)

    tx, unspent = btc_create_tx(msg_padded, oplist, 3, sender_pkscript, sat_value)
    txid = bitcoin_client.btc_sendrawtx(tx)
    print("txid:", txid)
    '''

    '''
    sender_pkscript = crypto.get_pkscript_by_addr(address)
    #txid = "79351b9fd9832eb6241b3b423c1ba51f5d1bdb56457784b44f5f8739daaf743c"
    #txid = "200ffaef2b7ee5e2666c8c384dc7e2ebd192c0f7d5d15894c01aacb086c401ab"
    txid = "2481ca31ffa2404cb1d6fa5c658760e01a34f62590e5ef1f6c467a9a78d602cf"
    tx_hex = bitcoin_client.btc_getrawtransaction2(txid)
    tx = serialize.parse_txbuf(tx_hex)
    tx_list = list()
    tx_list.append(tx)
    rawmsg_padded = btc_get_rawmsg(tx_list[0], sender_pkscript)
    print("after_msg:", rawmsg_padded.hex())
    '''

    '''
    capacity = 14
    msg_padded = get_random_bytes(14)
    print("msg_before:", msg_padded.hex())
    eth_txmsg = prepare_ethtx_data(msg_padded)
    fromaddr = "0x05Dba3698f7d9ff0c1c4380252D189b4708f276A"

    txid = eth_send_tx(fromaddr, eth_txmsg)
    print("txid:", txid)
    '''

    fromaddr = "0x05Dba3698f7d9ff0c1c4380252D189b4708f276A"
    txid_list = ether_client.get_sender_txid(fromaddr, 0)
    raw_msg = eth_get_rawmsg(txid_list[0])
    print("after:", raw_msg.hex())

