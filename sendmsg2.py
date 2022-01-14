import random
from threading import Thread

import synchronize
import test

import DB_insert
import DB_select
import bitcoin_client
import ether_client
import litecoin_client
import serialize
import transaction
import crypto
import numpy


class Session:
    def __init__(self, is_send):
        self.dbname = None
        self.is_send = is_send
        self.iv_pushed = False
        self.msg_IV = None  # 16B
        self.aes_key = None  # 32B
        self.btc_address = None  # str
        self.ltc_address = None  # str
        self.eth_address = None  # str
        self.sequence = 0  # 32bits integer:session id(1B) + seqnum(3B)
        self.pull_seq = 0
        self.btc_blocknum = -1
        self.ltc_blocknum = -1
        self.eth_blocknum = -1
        self.bytes_sent = 0
        self.buf_bytes = b''  # bytes type
        self.msg_type = bytes.fromhex('00')

    # sending msg
    # set up a session
    def start(self, username, session_id, aes_key, btc_address, ltc_address, eth_address):
        self.dbname = username+".db"
        self.aes_key = aes_key
        self.btc_address = btc_address
        self.ltc_address = ltc_address
        self.eth_address = eth_address
        self.sequence = session_id << 24  # integer
        self.pull_seq = session_id << 24
        if self.is_send:
            self.msg_IV = crypto.get_random_bytes(16)
            self.buf_bytes += self.msg_IV
        self.iv_pushed = False

    def stage_file(self, text_bytes, msg_type):
        # 01表示文本文件，02表示音频文件mp3，03表示图片文件
        msg_size_bytes = int.to_bytes(len(text_bytes), 8, "big")
        self.buf_bytes = msg_type+msg_size_bytes+text_bytes

    def stage_text(self, text_bytes):
        msg_type=bytes.fromhex('00')
        msg_size_bytes = int.to_bytes(len(text_bytes), 8, "big")
        self.buf_bytes = msg_type+msg_size_bytes+text_bytes

    def send_all(self):
        # txs = list()  # list of tx object

        is_send = False
        msg = self.buf_bytes  # msg = msg_type+size+buf
        print("oringnal_msg:", msg.hex())
        origin_sequence = self.sequence
        o_bytes_sent = self.bytes_sent
        btc_sender_pkscript = crypto.get_pkscript_by_addr(self.btc_address)
        ltc_sender_pkscript = crypto.get_pkscript_by_addr(self.ltc_address)
        btc_oplist, btc_unspent_value = bitcoin_client.get_unspent(self.btc_address)  # just want to get unspent_value
        btc_sat_value = int(btc_unspent_value * 100000000)

        ltc_oplist, ltc_unspent_value = litecoin_client.get_unspent(self.ltc_address)
        ltc_sat_value = int(ltc_unspent_value * 100000000)
        eth_wei_value = ether_client.eth_getbalance(self.eth_address)

        try:
            btc_cnt=0
            ltc_cnt=0
            while msg != b'':
                if btc_cnt==20:
                    bitcoin_client.mining(self.btc_address,1)
                    btc_cnt=0
                if ltc_cnt==20:
                    litecoin_client.mining(self.ltc_address,1)
                    ltc_cnt=0
                # print("oplist:", oplist)
                # print(sat_value)
                #select_id = random.randint(1, 3)
                numpy.random.seed()
                p = numpy.array([0.45, 0.45, 0.1])
                select_id = numpy.random.choice([1, 2, 3], p=p.ravel())
                if self.sequence == origin_sequence and select_id == 3:
                    array = numpy.random.binomial(1, 0.5, 1)
                    tmp_id = array[0]  # item of array is 0 or 1
                    select_id = tmp_id+1
                if select_id == 1:
                    oplist, unspent_value = bitcoin_client.get_unspent(self.btc_address)  # just want to get oplist
                    #print("btc_oplist:", oplist)
                    if btc_sat_value < 0x90000:
                        raise Exception("insuffient balance")
                    capacity = len(oplist) * 35 + 3 * 4 + 40
                    msg_slice, msg = self.split_msg(msg, capacity - 4)
                    #print("remain msg:", msg.hex())
                    seq_bytes = int.to_bytes(self.sequence, 4, "big")
                    tx_slice = seq_bytes + msg_slice
                    self.sequence += 1
                    print("tx_msg_slice:", tx_slice.hex())
                    print("tx_msg_slice len:", len(tx_slice))
                    print("unspent_sat:", btc_sat_value)
                    tx, btc_sat_value = transaction.btc_create_tx(self.dbname, tx_slice, oplist, 3, btc_sender_pkscript, btc_sat_value)
                    txid = bitcoin_client.btc_sendrawtx(tx)
                    btc_cnt+=1
                    print("Broadcast a btc tx:", txid)
                # 2 is litecoin
                elif select_id == 2:
                    ltc_oplist, ltc_unspent_value = litecoin_client.get_unspent(self.ltc_address)
                    print(ltc_oplist)
                    if ltc_sat_value < 0x90000:
                        raise Exception("insuffient balance")
                    capacity = len(ltc_oplist) * 35 + 3 * 4 + 40
                    msg_slice, msg = self.split_msg(msg, capacity - 4)
                    #print("remain msg:", msg.hex())
                    seq_bytes = int.to_bytes(self.sequence, 4, "big")
                    tx_slice = seq_bytes + msg_slice
                    self.sequence += 1
                    print("tx_msg_slice:", tx_slice.hex())
                    print("tx_msg_slice len:", len(tx_slice))
                    print("unspent_sat:", ltc_sat_value)

                    tx, ltc_sat_value = transaction.ltc_create_tx(self.dbname, tx_slice, ltc_oplist, 3, ltc_sender_pkscript, ltc_sat_value)
                    txid = litecoin_client.ltc_sendrawtx(tx)
                    ltc_cnt+=1
                    print("Broadcast a ltc tx:", txid)
                # 3 is ether
                else:
                    capacity = 39
                    # msg_slice = msg_IV(first time)+{msg_type+size+buf}
                    msg_slice, msg = self.split_msg(msg, capacity-4)
                    #print("remain msg:", msg.hex())
                    seq_bytes = int.to_bytes(self.sequence, 4, "big")
                    tx_slice = seq_bytes+msg_slice
                    eth_txmsg = transaction.prepare_ethtx_data2(tx_slice)
                    self.sequence += 1
                    print("tx_msg_slice:", tx_slice.hex())
                    print("tx_msg_slice len:", len(tx_slice))
                    try:
                        username = self.dbname[:-3]
                        #txid = transaction.eth_send_tx(username, self.eth_address, eth_txmsg)
                        txid = ether_client.eth_sendrawtx(self.dbname, self.eth_address, eth_txmsg)
                    except:
                        raise Exception("eth send error")
                    print("Broadcast a eth tx:", txid)
                #txs.append(tx)
                #txid = bitcoin_client.btc_sendrawtx(serialize.tobuf_tx(tx).hex())
                #print("txid:", txid)
        except Exception as e:
            self.sequence = origin_sequence
            self.bytes_sent = o_bytes_sent
            #print("Error:", e)
            raise Exception("Error:", e)
        if msg == b'':
            self.buf_bytes = b''
            bitcoin_client.mining(self.btc_address,1)
            litecoin_client.mining(self.ltc_address,1)
            is_send = True
        return is_send

    def split_msg(self, msg, slice_size):
        slice_buf = b''
        bytes_cnt = 0
        if not self.iv_pushed:
            slice_buf += self.msg_IV
            self.iv_pushed = True
            bytes_cnt += 16
        ret = b''
        if len(msg) >= slice_size-1-bytes_cnt:
            ret += msg[:slice_size-1-bytes_cnt]
        else:
            ret += msg
        #print("before pad:", ret.hex())
        #print("before pad len:", len(ret))
        ret += bytes.fromhex('80')  # marks the slice msg's ending
        ret = crypto.pad_to_num(slice_size-bytes_cnt, ret)
        #print("before enc msg:", ret.hex())
        enc_ret = crypto.AES_CTR_encrypt(ret, self.aes_key, self.msg_IV)
        slice_buf += enc_ret
        msg = msg[slice_size-1-bytes_cnt:]
        return slice_buf, msg

    # reciving msg
    def find_iv(self):
        ret = DB_select.get_content_byrawmsg(self.dbname, self.sequence)
        #print("db_ret:", ret)
        if ret:
            content = ret
        else:
            return False
        self.msg_IV = content[:16]
        print("recover_IV:", self.msg_IV.hex())
        enc_content = content[16:]
        #("before dec tx_msg_slice:", enc_content.hex())
        dec_content = crypto.AES_CTR_decrypt(enc_content, self.aes_key, self.msg_IV)
        #print("dec_content:", dec_content.hex())
        pad = bytes.fromhex('00')
        while dec_content[-1:] == pad:
            dec_content = dec_content.rstrip(pad)
        tail = bytes.fromhex('80')
        if dec_content[-1:] == tail:
            dec_content = dec_content.rstrip(tail)
        else:
            raise Exception("wrong padding!")
        #print("after dec and unpad:", dec_content.hex())
        if not DB_select.check_sessionmsg(self.dbname, self.sequence):
            DB_insert.session_msg_insert(self.dbname, self.sequence, dec_content)
        self.sequence += 1
        return True

    def find_next(self):
        ret = DB_select.get_content_byrawmsg(self.dbname, self.sequence)
        if ret:
            content = ret
        else:
            return False
        enc_content = content
        dec_content = crypto.AES_CTR_decrypt(enc_content, self.aes_key, self.msg_IV)
        pad = bytes.fromhex('00')
        while dec_content[-1:] == pad:
            dec_content = dec_content.rstrip(pad)
        tail = bytes.fromhex('80')
        if dec_content[-1:] == tail:
            dec_content = dec_content.rstrip(tail)
        else:
            raise Exception("wrong padding!")
        if not DB_select.check_sessionmsg(self.dbname, self.sequence):
            DB_insert.session_msg_insert(self.dbname, self.sequence, dec_content)
        self.sequence += 1
        return True

    def pull_msg(self):
        o_pull_seq = self.pull_seq
        #print("pull_seq:", self.pull_seq)
        content = DB_select.get_session_msg(self.dbname, self.pull_seq)
        #print("pull_content:", content)
        if not content:
            self.pull_seq = o_pull_seq
            return False, False
        self.pull_seq += 1
        msg_type = content[:1]
        content = content[1:]
        # msg_type is text
        msg_sum_size = int.from_bytes(content[:8], "big")
        content = content[8:]
        got_len = len(content)  # the size of this slice msg
        this_content = content  # this content is the first sequence msg of a session
        print("sum_size:", msg_sum_size)
        msg_buf = this_content
        #print("first slice:", msg_buf)
        while got_len < msg_sum_size:
            next_content = DB_select.get_session_msg(self.dbname, self.pull_seq)
            if next_content:
                next_len = len(next_content)
                got_len += next_len
                msg_buf += next_content
                #print("next_slice:", next_content)
                #print("got_len:", got_len)
                #self.pull_seq += 1
                if got_len == msg_sum_size:
                    #msg_buf += next_content
                    break
            else:
                self.pull_seq = o_pull_seq
                raise Exception("wrong combine msg!")
            self.pull_seq += 1
            #print("got_len:", got_len)
        #print("msg_buf_hex:", msg_buf.hex())
        print("msg_len:", len(msg_buf))
        return msg_buf, msg_type


def btc_session_filter(user_dbname, address, block_since, session_id):
    sender_pkscript = crypto.get_pkscript_by_addr(address)
    tx_list, txid_list = transaction.btc_get_tx(address, block_since)
    #print("find tx_list:", tx_list)
    for i in range(len(tx_list)):
        raw_header = transaction.btc_get_rawmsg_header(tx_list[i])
        raw_session_int = int.from_bytes(raw_header[:1], "big")
        if raw_session_int == session_id:
            #print("recover btc txid is:", txid_list[i])
            raw_msg = transaction.btc_get_rawmsg(user_dbname,address, tx_list[i], sender_pkscript)
            #print("get raw_msg:", raw_msg.hex())
            sequence = int.from_bytes(raw_msg[:4], "big")
            if not DB_select.check_rawmsg(user_dbname, address, sequence):
                DB_insert.rawmsg_insert(user_dbname, address, sequence, raw_msg[4:])


def ltc_session_filter(user_dbname, address, block_since, session_id):
    sender_pkscript = crypto.get_pkscript_by_addr(address)
    tx_list, txid_list = transaction.ltc_get_tx(address, block_since)
    #print("find tx_list:", tx_list)
    for i in range(len(tx_list)):
        raw_header = transaction.ltc_get_rawmsg_header(tx_list[i])
        raw_session_int = int.from_bytes(raw_header[:1], "big")
        if raw_session_int == session_id:
            #print("recover ltc txid is:", txid_list[i])
            raw_msg = transaction.ltc_get_rawmsg(user_dbname, address, tx_list[i], sender_pkscript)
            #print("get raw_msg:", raw_msg.hex())
            sequence = int.from_bytes(raw_msg[:4], "big")
            if not DB_select.check_rawmsg(user_dbname, address, sequence):
                DB_insert.rawmsg_insert(user_dbname, address, sequence, raw_msg[4:])


def eth_session_filter(user_dbname, eth_address, eth_block_since, session_id):
    txid_list = ether_client.get_sender_txid(eth_address, eth_block_since)
    #print("eth txid_list:", txid_list)
    for i in range(len(txid_list)):
        raw_msg = transaction.eth_get_rawmsg(txid_list[i])
        raw_header = raw_msg[:4]
        raw_session_int = int.from_bytes(raw_header[:1], "big")
        if raw_session_int == session_id:
            #print("recover eth txid is:", txid_list[i])
            #print("get raw msg:", raw_msg.hex())
            sequence = int.from_bytes(raw_msg[:4], "big")
            if not DB_select.check_rawmsg(user_dbname, eth_address, sequence):
                DB_insert.rawmsg_insert(user_dbname, eth_address, sequence, raw_msg[4:])


def send_secret_msg(username, session_id, aes_key, btcaddr, ltcaddr, ethaddr, msg_byte):
    ss = Session(True)
    ss.start(username, session_id, aes_key, btcaddr, ltcaddr, ethaddr)
    ss.stage_text(msg_byte)
    try:
        is_send = ss.send_all()
    except:
        raise Exception("send msg failed")
    return is_send


def send_secret_file(username, session_id, aes_key, btcaddr, ltcaddr, ethaddr, msg_byte, msg_type):
    ss = Session(True)
    ss.start(username, session_id, aes_key, btcaddr, ltcaddr, ethaddr)
    ss.stage_file(msg_byte, msg_type)
    try:
        is_send = ss.send_all()
    except:
        raise Exception("send msg failed")
    return is_send


def receive_secret_msg(username, session_id, aes_key, btcaddr, ltcaddr, ethaddr):
    user_dbname = username + '.db'
    ss = Session(False)  # recieve session
    # 接收方要记住自己用的哪个地址进行通信的
    # btc_address = synchronize.btc_check_DHaddr(user_dbname,)
    ss.start(username, session_id, aes_key, btcaddr, ltcaddr, ethaddr)
    # session_filter: select the msg which belongs to the session
    btc_block_since = ss.btc_blocknum - 6
    ltc_block_since = ss.ltc_blocknum - 6
    # eth_block_since = ss.eth_blocknum - 20
    eth_block_since=0
    if btc_block_since < 0:
        btc_block_since = 0
    if ltc_block_since < 0:
        ltc_block_since = 0
    if eth_block_since < 0:
        eth_block_since = 0
    '''
    threads = []
    threads.append(Thread(target=btc_session_filter(user_dbname, ss.btc_address, btc_block_since, session_id)))
    threads.append(Thread(target=ltc_session_filter(user_dbname, ss.ltc_address, ltc_block_since, session_id)))
    threads.append(Thread(target=eth_session_filter(user_dbname, ss.eth_address, eth_block_since, session_id)))
    for t in threads:
        print(t)
        t.start()
    '''
    btc_session_filter(user_dbname, ss.btc_address, btc_block_since, session_id)
    ltc_session_filter(user_dbname, ss.ltc_address, ltc_block_since, session_id)
    eth_session_filter(user_dbname, ss.eth_address, eth_block_since, session_id)
    ss.btc_blocknum = bitcoin_client.btc_getblockcount()
    ss.ltc_blocknum = litecoin_client.ltc_getblockcount()
    ss.eth_blocknum = ether_client.eth_getblocknum()
    if not ss.iv_pushed:
        if ss.find_iv():
            ss.iv_pushed = True
    if ss.iv_pushed:
        while True:
            ret = ss.find_next()
            if not ret:
                break
    msgbuf, msgtype = ss.pull_msg()
    if not msgbuf:
        return None, None
    return msgbuf, msgtype


if __name__ == '__main__':
    btc_address = "mvQCVjDnKHPHDbMPsysPfJTfguBgYQ2jvD"
    ltc_address = "mvtP94nGqAhyBDDGoQQfXpa7JtTK6N6zpB"
    eth_address = "0xDa1FfFe89f3f86Da41582E7CfA1dd0008220Fc05"  # must be checksum address
    aes_key = bytes.fromhex("4f45d7ffcddaa00b8b13bffdc1727e35")
    username = 'Alice'

    '''
    ss = Session(True)
    #aes_iv = bytes.fromhex("8a1066ffdd4ef965f2cb8710134b4998")
    ss.start(username, 2, aes_key, btc_address, ltc_address, eth_address)
    print("IV:", ss.msg_IV.hex())
    file_path = 'D:\PycharmCode\Challet_canrun\sound.mp3'
    sound_b = test.file_to_byte(file_path)
    #text_byte = b'12345'*60
    #text_byte = b'hello'
    ss.stage_text(sound_b)
    is_send = ss.send_all()
    '''

    # **************************************************

    user_dbname = username+'.db'
    ss = Session(False)  # recieve session
    session_id = 2
    # 接收方要记住自己用的哪个地址进行通信的
    # btc_address = synchronize.btc_check_DHaddr(user_dbname,)
    ss.start(username, session_id, aes_key, btc_address, ltc_address, eth_address)
    # session_filter: select the msg which belongs to the session
    btc_block_since = ss.btc_blocknum - 6
    ltc_block_since = ss.ltc_blocknum - 6
    eth_block_since = ss.eth_blocknum - 20
    if btc_block_since < 0:
        btc_block_since = 0
    if ltc_block_since < 0:
        ltc_block_since = 0
    if eth_block_since < 0:
        eth_block_since = 0
    btc_session_filter(user_dbname, ss.btc_address, btc_block_since, session_id)
    ltc_session_filter(user_dbname, ss.ltc_address, ltc_block_since, session_id)
    eth_session_filter(user_dbname, ss.eth_address, eth_block_since, session_id)
    ss.btc_blocknum = bitcoin_client.btc_getblockcount()
    ss.ltc_blocknum = litecoin_client.ltc_getblockcount()
    ss.eth_blocknum = ether_client.eth_getblocknum()
    if not ss.iv_pushed:
        if ss.find_iv():
            ss.iv_pushed = True
    if ss.iv_pushed:
        while True:
            ret = ss.find_next()
            if not ret:
                break
    while True:
        if not ss.pull_msg():
            break



