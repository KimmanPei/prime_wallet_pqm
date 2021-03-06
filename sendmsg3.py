import random
import test
# 单独测试了比特币的交易费，和交易单大小情况
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

    # sending msg
    # set up a session
    def start(self, user_dbname, session_id, aes_key, btc_address, ltc_address, eth_address):
        self.dbname = user_dbname
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

    def stage_text(self, text_bytes):
        msg_type = bytes.fromhex('00')
        msg_size_bytes = int.to_bytes(len(text_bytes), 8, "big")
        self.buf_bytes = msg_type + msg_size_bytes + text_bytes

    def send_all(self):
        # txs = list()  # list of tx object
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
        btc_tx = list()
        ltc_tx = list()
        eth_tx = list()
        try:
            while msg != b'':
                # print("oplist:", oplist)
                # print(sat_value)
                '''
                numpy.random.seed()
                p = numpy.array([0.45, 0.45, 0.1])
                select_id = numpy.random.choice([1, 2, 3], p=p.ravel())
                if self.sequence == origin_sequence and select_id == 3:
                    array = numpy.random.binomial(1, 0.5, 1)
                    tmp_id = array[0]  # item of array is 0 or 1
                    select_id = tmp_id + 1
                if select_id == 1:
                '''
                oplist, unspent_value = bitcoin_client.get_unspent(self.btc_address)  # just want to get oplist
                # print("btc_oplist:", oplist)
                if btc_sat_value < 0x90000:
                    raise Exception("insuffient balance")
                capacity = len(oplist) * 35 + 3 * 4 + 40
                msg_slice, msg = self.split_msg(msg, capacity - 4)
                # print("remain msg:", msg.hex())
                seq_bytes = int.to_bytes(self.sequence, 4, "big")
                tx_slice = seq_bytes + msg_slice
                self.sequence += 1
                #print("tx_msg_slice:", tx_slice.hex())
                #print("tx_msg_slice len:", len(tx_slice))
                #print("unspent_sat:", btc_sat_value)
                tx, btc_sat_value = transaction.btc_create_tx(self.dbname, tx_slice, oplist, 3, btc_sender_pkscript,
                                                              btc_sat_value)
                print("oplistin_len:", len(oplist))
                print("serialize tx: ", serialize.tobuf_tx(tx).hex())
                print("tx_len:", len(serialize.tobuf_tx(tx).hex()))
                #btc_tx.append(tx)
                # 2 is litecoin
                '''
                elif select_id == 2:
                    ltc_oplist, ltc_unspent_value = litecoin_client.get_unspent(self.ltc_address)
                    print(ltc_oplist)
                    if ltc_sat_value < 0x90000:
                        raise Exception("insuffient balance")
                    capacity = len(ltc_oplist) * 35 + 3 * 4 + 40
                    msg_slice, msg = self.split_msg(msg, capacity - 4)
                    # print("remain msg:", msg.hex())
                    seq_bytes = int.to_bytes(self.sequence, 4, "big")
                    tx_slice = seq_bytes + msg_slice
                    self.sequence += 1
                    print("tx_msg_slice:", tx_slice.hex())
                    print("tx_msg_slice len:", len(tx_slice))
                    print("unspent_sat:", ltc_sat_value)

                    tx, ltc_sat_value = transaction.ltc_create_tx(self.dbname, tx_slice, ltc_oplist, 3,
                                                                  ltc_sender_pkscript, ltc_sat_value)
                    ltc_tx.append(tx)
                # 3 is ether
                else:
                    capacity = 14
                    # msg_slice = msg_IV(first time)+{msg_type+size+buf}
                    msg_slice, msg = self.split_msg(msg, capacity - 4)
                    # print("remain msg:", msg.hex())
                    seq_bytes = int.to_bytes(self.sequence, 4, "big")
                    tx_slice = seq_bytes + msg_slice
                    eth_tx_data = transaction.prepare_ethtx_data(tx_slice)
                    gas = int.from_bytes(eth_tx_data.gas_limit, "big")
                    price = int.from_bytes(eth_tx_data.gas_price, "big")
                    value = int.from_bytes(eth_tx_data.value, "big")
                    balance = ether_client.eth_getbalance(self.eth_address)
                    print("gas:", gas)
                    print("value:", value)
                    print("price:", price)
                    print("gas*price:", gas * price)
                    print("balance:", balance)
                    if gas * price + value > balance:
                        self.sequence = origin_sequence
                        self.bytes_sent = o_bytes_sent
                        raise Exception("eth insufficient funds")
                    self.sequence += 1
                    print("tx_msg_slice:", tx_slice.hex())
                    print("tx_msg_slice len:", len(tx_slice))
                    eth_tx.append(eth_tx_data)
                    '''
        except Exception as e:
            self.sequence = origin_sequence
            self.bytes_sent = o_bytes_sent
            # print("Error:", e)
            raise Exception("Error:", e)
        try:
            for tx in btc_tx:
                txid = bitcoin_client.btc_sendrawtx(tx)
                print("Broadcast a btc tx:", txid)
            for tx in ltc_tx:
                txid = litecoin_client.ltc_sendrawtx(tx)
                print("Broadcast a ltc tx:", txid)
            for tx in eth_tx:
                txid = transaction.eth_send_tx(self.eth_address, tx)
                print("Broadcast a eth tx:", txid)
        except Exception as e:
            self.sequence = origin_sequence
            self.bytes_sent = o_bytes_sent
            # print("Error:", e)
            raise Exception("After createtx, Error:", e)
        self.buf_bytes = b''
        # return txs

    def split_msg(self, msg, slice_size):
        slice_buf = b''
        bytes_cnt = 0
        if not self.iv_pushed:
            slice_buf += self.msg_IV
            self.iv_pushed = True
            bytes_cnt += 16
        ret = b''
        if len(msg) >= slice_size - 1 - bytes_cnt:
            ret += msg[:slice_size - 1 - bytes_cnt]
        else:
            ret += msg
        print("before pad:", ret.hex())
        print("before pad len:", len(ret))
        ret += bytes.fromhex('80')  # marks the slice msg's ending
        ret = crypto.pad_to_num(slice_size - bytes_cnt, ret)
        print("before enc msg:", ret.hex())
        enc_ret = crypto.AES_CTR_encrypt(ret, self.aes_key, self.msg_IV)
        slice_buf += enc_ret
        msg = msg[slice_size - 1 - bytes_cnt:]
        return slice_buf, msg

    # reciving msg
    def find_iv(self):
        ret = DB_select.get_content_byrawmsg(self.dbname, self.sequence)
        # print("db_ret:", ret)
        if ret:
            content = ret
        else:
            return False
        self.msg_IV = content[:16]
        print("recover_IV:", self.msg_IV.hex())
        enc_content = content[16:]
        print("before dec tx_msg_slice:", enc_content.hex())
        dec_content = crypto.AES_CTR_decrypt(enc_content, self.aes_key, self.msg_IV)
        print("dec_content:", dec_content.hex())
        pad = bytes.fromhex('00')
        while dec_content[-1:] == pad:
            dec_content = dec_content.rstrip(pad)
        tail = bytes.fromhex('80')
        if dec_content[-1:] == tail:
            dec_content = dec_content.rstrip(tail)
        else:
            raise Exception("wrong padding!")
        print("after dec and unpad:", dec_content.hex())
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
        print("pull_seq:", self.pull_seq)
        content = DB_select.get_session_msg(self.dbname, self.pull_seq)
        print("pull_content:", content)
        if not content:
            self.pull_seq = o_pull_seq
            return False
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
        print("first slice:", msg_buf)
        while got_len < msg_sum_size:
            next_content = DB_select.get_session_msg(self.dbname, self.pull_seq)
            if next_content:
                next_len = len(next_content)
                got_len += next_len
                msg_buf += next_content
                print("next_slice:", next_content)
                print("got_len:", got_len)
                # self.pull_seq += 1
                if got_len == msg_sum_size:
                    # msg_buf += next_content
                    break
            else:
                self.pull_seq = o_pull_seq
                raise Exception("wrong combine msg!")
            self.pull_seq += 1
            print("got_len:", got_len)
        print("msg_buf_hex:", msg_buf.hex())
        print("msg_len:", len(msg_buf))


def btc_session_filter(user_dbname, address, block_since, session_id):
    sender_pkscript = crypto.get_pkscript_by_addr(address)
    tx_list, txid_list = transaction.btc_get_tx(address, block_since)
    # print("find tx_list:", tx_list)
    for i in range(len(tx_list)):
        raw_header = transaction.btc_get_rawmsg_header(tx_list[i])
        raw_session_int = int.from_bytes(raw_header[:1], "big")
        if raw_session_int == session_id:
            print("recover btc txid is:", txid_list[i])
            raw_msg = transaction.btc_get_rawmsg(user_dbname, tx_list[i], sender_pkscript)
            print("get raw_msg:", raw_msg.hex())
            sequence = int.from_bytes(raw_msg[:4], "big")
            if not DB_select.check_rawmsg(user_dbname, address, sequence):
                DB_insert.rawmsg_insert(user_dbname, address, sequence, raw_msg[4:])


def ltc_session_filter(user_dbname, address, block_since, session_id):
    sender_pkscript = crypto.get_pkscript_by_addr(address)
    tx_list, txid_list = transaction.ltc_get_tx(address, block_since)
    # print("find tx_list:", tx_list)
    for i in range(len(tx_list)):
        raw_header = transaction.ltc_get_rawmsg_header(tx_list[i])
        raw_session_int = int.from_bytes(raw_header[:1], "big")
        if raw_session_int == session_id:
            print("recover ltc txid is:", txid_list[i])
            raw_msg = transaction.ltc_get_rawmsg(user_dbname, tx_list[i], sender_pkscript)
            print("get raw_msg:", raw_msg.hex())
            sequence = int.from_bytes(raw_msg[:4], "big")
            if not DB_select.check_rawmsg(user_dbname, address, sequence):
                DB_insert.rawmsg_insert(user_dbname, address, sequence, raw_msg[4:])


def eth_session_filter(user_dbname, eth_address, eth_block_since, session_id):
    txid_list = ether_client.get_sender_txid(eth_address, eth_block_since)
    print("eth txid_list:", txid_list)
    for i in range(len(txid_list)):
        raw_msg = transaction.eth_get_rawmsg(txid_list[i])
        raw_header = raw_msg[:4]
        raw_session_int = int.from_bytes(raw_header[:1], "big")
        if raw_session_int == session_id:
            print("recover eth txid is:", txid_list[i])
            print("get raw msg:", raw_msg.hex())
            sequence = int.from_bytes(raw_msg[:4], "big")
            if not DB_select.check_rawmsg(user_dbname, eth_address, sequence):
                DB_insert.rawmsg_insert(user_dbname, eth_address, sequence, raw_msg[4:])


if __name__ == '__main__':
    btc_address = "n2RGHTqKBRZimC2L89MwiGuTiszyYbscEu"
    ltc_address = "mgqotZrWSRnmJU95W49YE68SB2B5BeMieu"
    eth_address = "0x9B66661db7B65792f4cFb0C7114C001Ba974e9A6"  # must be checksum address
    aes_key = bytes.fromhex("4f45d7ffcddaa00b8b13bffdc1727e35")
    user_dbname = 'Alice.db'

    ss = Session(True)
    # aes_iv = bytes.fromhex("8a1066ffdd4ef965f2cb8710134b4998")
    ss.start(user_dbname, 6, aes_key, btc_address, ltc_address, eth_address)
    #print("IV:", ss.msg_IV.hex())
    text_b = b'hello world'
    ss.stage_text(text_b)
    ss.send_all()

    # **************************************************
    '''
    ss = Session(False)  # recieve session
    session_id = 9
    ss.start(user_dbname, session_id, aes_key, btc_address, ltc_address, eth_address)
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
    '''


