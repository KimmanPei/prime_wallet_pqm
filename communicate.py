import base64
import os

import bitcoin_client
import crypto
import litecoin_client
import random
import threading

import ether_client
import DB_select
global LTC_TXID_LIST
LTC_TXID_LIST=[]
global BTC_TXID_LIST
BTC_TXID_LIST=[]
global ETH_TXID_LIST
ETH_TXID_LIST=[]
global BTH_TXID_LIST
BTH_TXID_LIST=[]
global MSG_SHD_NUM

import datetime


def check_senderDHaddr_format(from_address, to_address, cointype):
    from_is_valid = False
    if to_address == 'compute_DHaddr':
        if cointype == 'BTC':
            from_is_valid = bitcoin_client.validate_address(from_address)
        elif cointype == 'LTC':
            from_is_valid = litecoin_client.validate_address(from_address)
        elif cointype=='ETH':
            from_is_valid = ether_client.eth_isvalid_addr(from_address)
    return from_is_valid


# btc_DHaddr,ltc_DHaddr和eth_addr一起接收核对
def check_receiverDHaddr_format(from_address, to_address):
    addr_dict = dict()
    is_valid = True
    if to_address != "check_DHaddr":
        is_valid = False
        return is_valid, addr_dict
    id = from_address.index(";")
    btcaddr = from_address[:id]
    if not bitcoin_client.validate_address(btcaddr):
        is_valid = False
    from_address = from_address[id + 1:]
    id=from_address.index(";")
    ltcaddr = from_address[:id]
    ethaddr=from_address[id+1:]
    print("btc:",btcaddr)
    print("ltc:", ltcaddr)
    print("eth:",ethaddr)
    if not litecoin_client.validate_address(ltcaddr):
        is_valid = False
    if not ether_client.eth_isvalid_addr(ethaddr):
        is_valid=False
    addr_dict['btcaddr'] = btcaddr
    addr_dict['ltcaddr'] = ltcaddr
    addr_dict['ethaddr'] = ethaddr
    return is_valid, addr_dict


def check_sendtext_format(from_address, to_address):
    addr_dict = dict()
    is_valid = True
    if to_address != "addr":
        is_valid = False
        return is_valid, addr_dict
    id = from_address.index(";")
    btcaddr = from_address[:id]
    if not bitcoin_client.validate_address(btcaddr):
         is_valid = False
    from_address = from_address[id + 1:]
    id = from_address.index(";")
    ltcaddr = from_address[:id]
    if not litecoin_client.validate_address(ltcaddr):
        is_valid = False
    from_address = from_address[id + 1:]
    ethaddr = from_address
    addr_dict['btcaddr']=btcaddr
    addr_dict['ltcaddr']=ltcaddr
    addr_dict['ethaddr']=ethaddr
    return is_valid, addr_dict


def check_sendfile_format(note):
    if note == 'file':
            return True
    return False


def second_check_sendfile_format(fromaddr, toaddr, filename):
    addr_dict = dict()
    is_valid = True
    if toaddr != "addr":
        is_valid = False
        return is_valid, addr_dict
    if not filename:
        return False, addr_dict
    id = fromaddr.index(";")
    btcaddr = fromaddr[:id]
    if not bitcoin_client.validate_address(btcaddr):
        is_valid = False
    from_address = fromaddr[id + 1:]
    id = from_address.index(";")
    ltcaddr = from_address[:id]
    if not litecoin_client.validate_address(ltcaddr):
        is_valid = False
    from_address = from_address[id + 1:]
    ethaddr = from_address
    addr_dict['btcaddr'] = btcaddr
    addr_dict['ltcaddr'] = ltcaddr
    addr_dict['ethaddr'] = ethaddr
    return is_valid, addr_dict


def check_receivetext_format(fromaddr, toaddr):
    is_valid=bitcoin_client.validate_address(fromaddr)
    if is_valid and toaddr=='receive':
        return True
    return False


def get_msgtype(filename):
    index=filename.index(".")
    typestr=filename[index+1:]
    print("typestr", typestr)
    msgtype = None
    if typestr == 'txt':
        msgtype = bytes.fromhex('01')
    elif typestr=='mp3' or typestr == 'wav':
        msgtype = bytes.fromhex('02')
    elif typestr == 'jpg' or typestr =='png':
        msgtype = bytes.fromhex('03')
    return msgtype


def rebuild_file(msgtype, msgbuf):
    real_bytes = base64.b64decode(msgbuf)
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = BASE_DIR + "\\media\\"
    path="D:\PycharmCode\Challet_canrun\static"
    #print(path)
    if msgtype == bytes.fromhex('01'):
        path += "\\recover.txt"
    if msgtype == bytes.fromhex('02'):
        path += "\\recover.mp3"
        with open(path, 'wb') as fp:
            fp.write(real_bytes)
    elif msgtype == bytes.fromhex('03'):
        path += "\\recover.jpg"
        with open(path, 'wb') as fp:
            fp.write(real_bytes)
    print("path", path)
    file_name = path.split("\\")[-1]
    file = open(path.replace(" ", ""), 'rb')
    return file, file_name


def delete_file(filename):
    path = "D:\\PycharmCode\\Challet_canrun\\static\\"+filename
    print(path)
    if os.path.exists(path):
        os.remove(path)
        print('成功删除文件:', path)


class TestThread(threading.Thread):
    def __init__(self, func, args=()):
        super(TestThread, self).__init__()
        self.func = func
        self.args = args

    def run(self):
        self.result = self.func(*self.args)

    def get_result(self):
        try:
            return self.result  # 如果子线程不使用join方法，此处可能会报没有self.result的错误
        except Exception:
            return None

if __name__ == '__main__':
     filename='test.txt'
     # delete_file(filename)
     print(get_msgtype(filename).hex())
