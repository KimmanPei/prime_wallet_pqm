# this file is used to transform the tx and related variable into little endian and serialize them
import script
from transaction import *


# transform txid(hexstring) to little endian bytes
def to_lebuf_txid(hex_txid):
    txid_bytes = bytes.fromhex(hex_txid)
    final_bytes = txid_bytes[::-1]
    return final_bytes


# after serializing, vout is 4 bytes in little endian
def tobuf_outpoint(outpoint):
    buf_bytes = to_lebuf_txid(outpoint.txid)
    buf_bytes = buf_bytes + int.to_bytes(outpoint.vout, 4, "little")
    #print("outpoint:", buf_bytes.hex())
    return buf_bytes


# transfrom script_size to Varint type and serialize it
def to_Varintbuf_size(size):
    if size <= 0xfc:
        size_byte = int.to_bytes(size, 1, "little")
        return size_byte
    elif size <= 0xffff:
        prefix = 'fd'.encode("utf-8")
        size_byte = prefix + int.to_bytes(size, 2, "little")
        return size_byte
    elif size <= 0xffffffff:
        prefix = 'fe'.encode("utf-8")
        size_byte = prefix + int.to_bytes(size, 4, "little")
        return size_byte
    else:
        prefix = 'ff'.encode("utf-8")
        size_byte = prefix + int.to_bytes(size, 8, "little")
        return size_byte


# to get correct opcode by the size of which in script_sig
def get_opcode(length):
    if length < script.OP_PUSHDATA1:
        len_bytes = int.to_bytes(length, 1, "little")
        buf_bytes = len_bytes
    elif length <= 0xff:
        len_bytes = int.to_bytes(length, 1, "little")
        buf_bytes = int.to_bytes(script.OP_PUSHDATA1, 1, "big") + len_bytes
    elif length <= 0xffff:
        len_bytes = int.to_bytes(length, 2, "little")
        buf_bytes = int.to_bytes(script.OP_PUSHDATA2, 1, "big") + len_bytes
    else:
        len_bytes = int.to_bytes(length, 4, "little")
        buf_bytes = int.to_bytes(script.OP_PUSHDATA4, 1, "big") + len_bytes
    return buf_bytes


# add OP code to sig_script
# example: 47(sig's size,the format is decided by size) 3044...01(sig including 0x01) 21(pk's size) 02...(pk)
def tobuf_sigscript(sig, pk_bytes):
    buf_sig = get_opcode(len(sig)) + sig
    buf_pk = get_opcode(len(pk_bytes)) + pk_bytes
    return buf_sig + buf_pk


# sequence in txin is bytes type
# serialized sequence is 4 bytes in little endian, txin.sequence is already bytes type
def tobuf_txin(txin):
    buf_bytes = tobuf_outpoint(txin.preout)
    if txin.script_size:
        buf_bytes += to_Varintbuf_size(txin.script_size)
    else:
        buf_bytes += bytes.fromhex("00")
    if txin.script_sig:
        buf_bytes += txin.script_sig
    seq = txin.sequence
    seq_buf = seq[::-1]  # little endian
    buf_bytes += seq_buf
    return buf_bytes


# pk_script is the 20 bytes hash of pk,this function adds OP code to pk_script
def tobuf_pkscript(pk_script):
    '''
    OP_DUP
    OP_HASH160
    20(pk_script.size)
    pk_script
    OP_EQUALVERIFY
    OP_CHECKSIG
    '''
    buf_bytes = int.to_bytes(script.OP_DUP, 1, "big")
    buf_bytes = buf_bytes + int.to_bytes(script.OP_HASH160, 1, "big")
    pksize = 20 # size of pk_script
    buf_bytes += int.to_bytes(pksize, 1, "big")
    buf_bytes += pk_script
    buf_bytes += int.to_bytes(script.OP_EQUALVERIFY, 1, "big")
    buf_bytes += int.to_bytes(script.OP_CHECKSIG, 1, "big")
    return buf_bytes


# data is the data of nulldata
def tobuf_nulldata(data):
    '''
    OP_RETURN
	nulldata.size
    data
    '''
    buf_bytes = int.to_bytes(script.OP_RETURN, 1, "big")
    buf_bytes += int.to_bytes(len(data), 1, "little") + data
    return buf_bytes


# serialized value is 8 bytes in little endian
# script_pubkey is already serialized
def tobuf_txout(txout):
    buf_bytes = int.to_bytes(txout.value, 8, "little")
    buf_bytes = buf_bytes + to_Varintbuf_size(txout.script_size)
    buf_bytes = buf_bytes + txout.script_pubkey
    return buf_bytes


# the number of txin and txout are transformed to varint type
# locktime is serialized to 4 Bytes little endian
def tobuf_tx(tx):
    buf_version = int.to_bytes(tx.version, 4, "little")
    buf_txin_cnt = to_Varintbuf_size(len(tx.txin_list))
    buf_alltxin = b''
    buf_alltxout = b''
    for i in range(len(tx.txin_list)):
        buf_alltxin += tobuf_txin(tx.txin_list[i])
    buf_txout_cnt = to_Varintbuf_size(len(tx.txout_list))
    for i in range(len(tx.txout_list)):
        buf_alltxout += tobuf_txout(tx.txout_list[i])
    buf_locktime = int.to_bytes(tx.locktime, 4, "little")
    buf_tx = buf_version + buf_txin_cnt + buf_alltxin + buf_txout_cnt + buf_alltxout + buf_locktime
    return buf_tx


# return the size in integer type
def parse_Varintbuf(size_buf):
    txbuf = size_buf
    if size_buf[:1] == bytes.fromhex("fd"):
        size = int.from_bytes(size_buf[1:3], "little")
        txbuf = txbuf[3:]
    elif size_buf[:1] == bytes.fromhex("fe"):
        size = int.from_bytes(size_buf[1:5], "little")
        txbuf = txbuf[5:]
    elif size_buf[:1] == bytes.fromhex("ff"):
        size = int.from_bytes(size_buf[1:9], "little")
        txbuf = txbuf[9:]
    else:
        size = size_buf[0]
        txbuf = txbuf[1:]
    return size, txbuf


def parse_txbuf(tx_hex):
    tx_buf = bytes.fromhex(tx_hex)
    # print("first buf:", tx_buf.hex())
    version_buf = tx_buf[:4]
    version = int.from_bytes(version_buf, "little")
    tx_buf = tx_buf[4:]
    txin_cnt, tx_buf = parse_Varintbuf(tx_buf)
    txin_list = list()
    for i in range(txin_cnt):
        txid = tx_buf[:32][::-1].hex()
        tx_buf = tx_buf[32:]
        vout = int.from_bytes(tx_buf[:4], "little")
        tx_buf = tx_buf[4:]
        preout = Outpoint(txid, vout)
        script_size, tx_buf = parse_Varintbuf(tx_buf)
        script_sig = tx_buf[:script_size]
        tx_buf = tx_buf[script_size:]
        sequence = tx_buf[:4][::-1]
        tx_buf = tx_buf[4:]
        txin = Tx_in(preout, script_size, script_sig, sequence)
        txin_list.append(txin)
    txout_cnt, tx_buf = parse_Varintbuf(tx_buf)
    txout_list = list()
    for i in range(txout_cnt):
        value = int.from_bytes(tx_buf[:8], "little")
        tx_buf = tx_buf[8:]
        script_size, tx_buf = parse_Varintbuf(tx_buf)
        script_pk = tx_buf[:script_size]
        tx_buf = tx_buf[script_size:]
        txout = Tx_out(value, script_size, script_pk)
        txout_list.append(txout)
    locktime = int.from_bytes(tx_buf[:4], "little")
    tx = Tx(version, txin_list, txout_list, locktime)
    return tx


def parse_scriptsig(script_sig):
    #print("script_sig:", script_sig.hex())
    if script_sig[0] == script.OP_PUSHDATA1:
        sig_len = script_sig[1]  # bytes[i] is the integer related to the byte
        script_sig = script_sig[2:]
        sig = script_sig[:sig_len-1]
    elif script_sig[0] == script.OP_PUSHDATA2:
        sig_lenbuf = script_sig[1:3]
        sig_len = int.from_bytes(sig_lenbuf, "little")
        script_sig = script_sig[3:]
        sig = script_sig[:sig_len-1]
    elif script_sig[0] == script.OP_PUSHDATA4:
        sig_lenbuf = script_sig[1:5]
        sig_len = int.from_bytes(sig_lenbuf, "little")
        script_sig = script_sig[5:]
        sig = script_sig[:sig_len-1]
    else:
        sig_len = script_sig[0]
        sig = script_sig[1:sig_len]  # remove the last HASH-type0x01
    return sig


def parse_scriptpk(script_pk):
    if script_pk[0] == script.OP_DUP:
        if script_pk[1] == script.OP_HASH160:
            script_pk = script_pk[3:]
            pk_script = script_pk[:20]
            return pk_script
        else:
            raise Exception("script_pk OP_HASH160 parse error")
    elif script_pk[0] == script.OP_RETURN:
        size = script_pk[1]
        nulldata = script_pk[2:size+2]
        #print("nulldata:", nulldata.hex())
        return nulldata
    else:
        raise Exception("script_pk  parse error")


if __name__ == '__main__':
    #bitcoin_client.btc_getrawtransaction2(txid)
    pass