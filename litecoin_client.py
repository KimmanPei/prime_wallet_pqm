from decimal import Decimal
from queue import Queue

import DB_insert
import DB_select
import crypto
from collections import namedtuple
import re
#import encryption_ltc as encryption
import random
import socket
import json
import sys
import paramiko
import hashlib
import base58
import binascii
import datetime

import serialize
import test

fix_cmd2 = "litecoin-cli -datadir=/home/peiqianman/.litecoin/ -conf=/home/peiqianman/.litecoin/litecoin.conf  -rpcport=19031 "
# 比特币客户端bitcoin.exe所在地址
# path="D:\\litecoin-0.17.1\\bin\\"
# bitcoin测试网络运行时的固定指令
fix_cmd = "./litecoinServer/litecoin-0.17.1/bin/litecoin-cli -regtest "
# fix_cmd="litecoin-cli -regtest "
fp=open("log.txt","w",encoding='utf-8')
RECEIVE_CHANGE_ADDRESS = "QU92WD1fgS2CQUZCcHVkZGaGpBbYzXYvVW"
# 将当前路径移至对应路径下，执行相应命令cmd，并将结果以字符串形式返回
ORDER_STAMP = ['00000', '00001', '00010', '00011', '00100', '00101', '00110', '00111',
               '01000', '01001', '01010', '01011', '01100', '01101', '01110', '01111',
               '10000', '10001', '10010', '10011', '10100', '10101', '10110', '10111',
               '11000', '11001', '11010', '11011', '11100', '11101', '11110', '11111']

global LAST_TIME
LAST_TIME=1596861684


def execute_cmd(cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.load_system_host_keys()
    client.connect("192.144.175.67", port=22, username="ubuntu", password='QkDfZWg,52M%=7e')
    stdin, stdout, stderr = client.exec_command(cmd)
    output = stdout.read()
    error = stderr.read()
    if error:
        ex = Exception("命令行运行错误，错误为：\n" + error.decode() + "\n运行的命令行为: " + str(cmd))
        raise ex
    client.close()
    return output.decode()


def get_LTC_account_addresses(account):
    all_addresses = ltc_listaddressgroupings()
    # print(all_addresses)
    if account not in all_addresses.keys():
        return {}
    return all_addresses[account]

"""
def execute_cmd(cmd):
    os.chdir(path)
    f = os.popen(cmd, 'r')
    ret = f.read()
    return ret
"""


# 创建一个新的地址
# get_LTC_account_addresses(account)
# add_LTC_account_address(account)
def ltc_getnewaddress(account):  #
    tmp_cmd = fix_cmd + "getnewaddress " + account
    print("cmd：", tmp_cmd)
    return execute_cmd(tmp_cmd)


# 挖矿
def ltc_generatetoaddress(n_block, address):
    tmp_cmd = fix_cmd + "generatetoaddress " + str(n_block) + ' "' + address + '"'
    return execute_cmd(tmp_cmd)


# 列出当前所有地址及所持比特币及其标签
# 返回一个字典，字典结构为{laber: {address:value,..},..}
# my version:返回一个列表，字典的结构为[(address,value)],根据value从大到小排列
def ltc_listaddressgroupings():
    '''
    tmp_cmd = fix_cmd + "listaddressgroupings"
    d = execute_cmd(tmp_cmd)
    # print('output:', d)
    d = re.sub('[, [\]\n]', '', d)
    # print('去掉， \\\\n', d)
    d = d.split('"')
    # print('去掉"', d)
    addresses = []
    num_address = int(len(d) / 4)
    for i in range(num_address):
        addresses.append([d[i * 4 + 1], d[i * 4 + 2]])
    addresses = sorted(addresses, key=lambda x: x[1], reverse=True)
    return addresses
    '''
    tmp_cmd = fix_cmd + "listaddressgroupings"
    d = execute_cmd(tmp_cmd)
    # print('output:', d)
    d = re.sub('[, [\]\n]', '', d)
    # print('去掉无用字符， \\\\n', d)
    d = d.split('"')
    # print('去掉"', d)
    addresses = dict()
    # print(d)
    num_address = int(len(d) / 4) + 1
    # 识别默认账号
    # for i in range(num_address):
    #     if d[(i+1) * 4] != "" or i == num_address - 1:
    #         addresses['null'] = {d[(i+1) * 4 - 3]: d[(i+1) * 4 - 2]}
    #         d.pop((i+1) * 4 - 3)
    #         d.pop((i + 1) * 4 - 3)
    #         break
    d.pop(0)
    for i in range(num_address - 1):
        # print(d[i*4+2])
        # print(list(addresses.keys()))
        # keys = list(addresses.keys())
        if d[i * 4 + 2] in addresses.keys():
            # print("repeat", addresses[d[i*4+2]])
            addresses[d[i * 4 + 2]][d[i * 4]] = d[i * 4 + 1]
        else:
            addresses[d[i * 4 + 2]] = {d[i * 4]: d[i * 4 + 1]}
        # print(addresses)
    return addresses

def get_time_sender_order(txid):
    tx = get_transaction(txid)
    AVs, sender = get_AV_from_hex(tx['hex'])
    for i in range(len(AVs)):
        if AVs[i][0] not in sender:
            order = ORDER_STAMP.index(get_addr_tail(AVs[0][0], 5))
            return tx['time'], sender, order
    print("sender:", sender)
    print("AVs:", AVs)
    print("183error")


def ltc_getrawtransaction(txid):
    cmd = fix_cmd2 + "getrawtransaction " + '"' + txid + '"'
    result = ltc_execute_cmd2(cmd)
    return result


def ltc_decoderawtx(hex):
    cmd = fix_cmd + "decoderawtransaction " + '"' + hex + '"'
    result = execute_cmd(cmd)
    return eval(result)


def get_AV_from_hex(hex):
    rawtx = ltc_decoderawtx(hex)
    AV = []
    sender = []
    for item in rawtx['vin']:
        result = get_transaction(item['txid'])
        sender.append(result["details"][item["vout"]]["address"])

    for item in rawtx['vout']:
        AV.append((item['scriptPubKey']["addresses"][0], item['value']))
    return AV, sender

'''
def ltc_createrawtransaction(TX, ADDRESSES_VALUE):
    # print('TX:', TX, '\n', 'AN对：', ADDRESSES_VALUE)
    tmp_cmd = fix_cmd + 'createrawtransaction "['

    for txid in TX:
        tmp_cmd = tmp_cmd + '{\\"txid\\":\\"%s\\",\\"vout\\":%s},' % (txid['txid'], txid['vout'])
    tmp_cmd = tmp_cmd[:-1] + ']\" \"{'

    print("ADDRESSES_VALUE start", file=fp)
    for address_value in ADDRESSES_VALUE:
        #print(address[0], ":", address[1], file=fp)
        #tmp_cmd = tmp_cmd + '\\\"%s\\\":%.8f,' % (address[0], address[1])
        tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (address_value['address'], address_value['value'])
    # print("ADDRESSES_VALUE end",file=fp)
    tmp_cmd = tmp_cmd[:-1] + '}"'
    # print(tmp_cmd)
    rawtx = execute_cmd(tmp_cmd)
    rawtx = rawtx.strip()
    return rawtx
'''


def ltc_createrawtransaction(TX, ADDRESSES_VALUE):
    print('UTXO:', TX, '\n', 'AV对：', ADDRESSES_VALUE)
    tmp_cmd = fix_cmd + 'createrawtransaction "['

    for txid in TX:
        tmp_cmd = tmp_cmd + '{\\"txid\\":\\"%s\\",\\"vout\\":%s},' % (txid['txid'], txid['vout'])
    tmp_cmd = tmp_cmd[:-1] + ']\" \"{'

    for address_value in ADDRESSES_VALUE:
        tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (address_value['address'], address_value['value'])
    tmp_cmd = tmp_cmd[:-1] + '}"'
    print(tmp_cmd)
    return execute_cmd(tmp_cmd)


# 发送交易单
def ltc_sendrawtransaction(signed_rawtx):
    tmp_cmd = fix_cmd2 + "sendrawtransaction " + ' "' + signed_rawtx + '"'
    return ltc_execute_cmd2(tmp_cmd)


# 查找某地址未被花费的UTXO
# 其中confirm_min为被确认次数的最小值
# 返回一个字典字典结构为{txid : {该txid对应的UTXO中的信息}, ...}
# 该txid对应的UTXO中的信息也以字典形式返回，eg:{'vout': '0', ..}
# 信息包括vout, address, label, redeemScript, scriptPubKey, amount, confirmations, spendable, solvabel, desc, safe
# 及以txid为唯一索引建立的字典
# my version:返回一个列表，表示地址的全部utxo,返回值按照utxo的值从大到小排序,先花费大的utxo：
# [('7a5b85bcd27414999afa8d7cc82b7338659a6869922613d00295e169e6031e00', [0, 50.0]), ('7381ac367110ab8b268fe06c237530ee4bae8e270abb64394c685eb9ea928d00', [0, 50.0]))
"""
def ltc_listunspent(address):
    true = True
    false = False
    cmd = fix_cmd + "listunspent"
    result = execute_cmd(cmd)
    result = eval(result)
    utxo = []
    for item in result:
        if item['address'] == address and item['amount'] > 0:
            utxo.append((item['txid'], [item['vout'], item['amount']]))
    return utxo
"""

'''
def ltc_listunspent(address):
    true = True
    false = False
    tmp_cmd = fix_cmd + 'listunspent 1 999999 '
    tmp_cmd += '"[\\"' + address + '\\"]"'
    print(tmp_cmd)
    result = eval(execute_cmd(tmp_cmd))
    ret = {}
    for res in result:
        txid = res['txid']
        vout = res['vout']
        amount = res['amount']
        ret[txid] = [vout, amount]
    ret = sorted(ret.items(), key=lambda x: x[1][1], reverse=True)
    return ret

    for i in range(UTXO_num):
        start_index = i * UTXO_PARA_num  # {txid:vout,amount}
        ret[UTXO[start_index + 1]] = [int(UTXO[start_index + 3]), float(UTXO[start_index + 13])]

    # print(ret)
    ret = sorted(ret.items(), key=lambda x: x[1][1], reverse=True)
    # 返回值按照utxo的值从大到小排序,先花费大的utxo
    return ret
'''
def ltc_listunspent(confirm_min, confirm_max, address):
    UTXO_PARA_num = 11  # 一个UTXO中的参数个数
    tmp_cmd = fix_cmd + 'listunspent ' + str(confirm_min) + ' ' + str(confirm_max) + ' '
    tmp_cmd += '"[\\"' + address + '\\"]"'
    # print(tmp_cmd)
    UTXO = execute_cmd(tmp_cmd)
    print("UTXO:", UTXO)
    print("UTXO_len:", len(UTXO))
    UTXO = re.sub('[, :{}[\]\n]', '', UTXO)
    # print(UTXO)
    UTXO = UTXO.replace('""', '"')
    # print(UTXO)
    UTXO = UTXO[1:].split('"')
    UTXO_num = int(len(UTXO) / (UTXO_PARA_num * 2))
    ret = dict()
    for i in range(UTXO_num):
        start_index = i * UTXO_PARA_num * 2  # 在UTXO中txid这个字符串所在的位置索引
        ret[UTXO[start_index + 1]] = dict()
        for j in range(int(UTXO_PARA_num - 1)):
            ret[UTXO[start_index + 1]][UTXO[start_index + 2 + j * 2]] = UTXO[start_index + 3 + j * 2]
            # print(i * UTXO_PARA_num + 2 + j * 2, i * UTXO_PARA_num + 3 + j * 2)
    print(ret)
    return ret

#address="QLgX8VCFhrAduD5p4nEh23JehNHixfds8s"
#ltc_listunspent(1,99999,address)

# 返回某地址的私钥
def ltc_dumpprivkey(address):
    tmp_cmd = fix_cmd + 'dumpprivkey ' + address
    privatekey = execute_cmd(tmp_cmd)
    return privatekey[:-1]


def ltc_sign_withkey(raw_hex, private_key):
    tmp_cmd = fix_cmd2 + 'signrawtransactionwithkey ' + raw_hex + ' [\\"' + private_key + '\\"]'
    tmp_cmd = tmp_cmd.replace("\n", "")
    hex = ltc_execute_cmd2(tmp_cmd)
    hex_split = hex.split('"')
    return hex_split[3]


def ltc_decoderawtransaction(txid):
    tmp_cmd = fix_cmd + 'decoderawtransaction '
    tmp_cmd += '"' + txid + '"'
    return execute_cmd(tmp_cmd)


# # 发送裸交易
# def ltc_sendrawtransaction(signed_hex):
#     tmp_cmd = fix_cmd + 'sendrawtransaction ' + signed_hex
#     return execute_cmd(tmp_cmd)


# msg为要隐匿的消息，lamda为两个λ，将两个λ分别插入消息前后
# 并在插入后的前后位置生成随机字符串，并检查是否包含λ子串，如有则重新生成
# rdm_str 的长度为len(msg)/4-len(msg)/2之间的随机值
# λ长度为17bit
def create_shadow_msg(msg, lamda):
    MIN_SIZE = int(len(msg) / 4)
    MAX_SIZE = len(msg)
    # 生成λ_start前面的字符串
    start_str = encryption.create_rdmbin_str_exclude(random.randint(MIN_SIZE, MAX_SIZE), lamda[0])
    end_str = encryption.create_rdmbin_str_exclude(random.randint(MIN_SIZE, MAX_SIZE), lamda[1], 'tail')
    shadow_msg = start_str + lamda[0] + msg + lamda[1] + end_str
    test.write_file('ltc_log.txt', 'valid_message:' + msg)
    test.write_file('ltc_log.txt', 'lamda_start:' + lamda[0])
    test.write_file('ltc_log.txt', 'lamda_end:' + lamda[1])
    test.write_file('ltc_log.txt', 'random_str_start:' + start_str)
    test.write_file('ltc_log.txt', 'random_str_end:' + end_str)
    test.write_file('ltc_log.txt', 'hidden_message_all' + shadow_msg)
    print("in create shadow message")
    print("rdm_str1:", start_str, file=fp)
    print("lamda_start:", lamda[0], file=fp)
    print("msg:", msg, file=fp)
    print("lamda_end:", lamda[1], file=fp)
    print("rdm_str2:", end_str, file=fp)
    print("text_shadow:", shadow_msg, file=fp)
    return shadow_msg


# 连接γ_start,info,γ_end,并补全至21位
# 其中gama为一个含有两个元素的列表，包含γ_start,info,γ_end
def create_value(msg, gama):
    print('value_msg:', msg)
    VALUE_LEN = 21
    DEC_NUM = 8
    msg_shadow = gama[0] + msg + gama[1]
    str_len = VALUE_LEN - len(msg_shadow)
    start_str_num = random.randint(2, str_len - 2)
    # print(start_str_num)
    end_str_num = str_len - start_str_num
    # print(end_str_num)
    start_str = encryption.create_rdmbin_str_exclude(start_str_num, gama[0])
    end_str = encryption.create_rdmbin_str_exclude(end_str_num, gama[1], 'tail')
    value_bin = start_str + msg_shadow + end_str
    print('value_bin:', value_bin)
    value_dec = int(value_bin, 2)
    # print(value_dec)
    value = encryption.int2nfloat(str(value_dec), DEC_NUM)  # 将十进制的value转化为小数点后有8位的小数
    return value

def get_transaction(txid):
    tmp_cmd = fix_cmd + 'gettransaction '
    tmp_cmd += '"' + txid + '"'
    true = True
    false = False
    result = execute_cmd(tmp_cmd)
    # print("288len(result):",len(result))
    # print("result:",result)
    tx = eval(result)
    return tx


# 提取函数ltc_listaddressgroupings返回值中的所有地址
def get_addresses():
    """groupings = ltc_listaddressgroupings()
    labels = list(groupings.keys())
    addresses = list()
    for label in labels:
        addresses += list(groupings[label].keys())
    """
    tmp_cmd = fix_cmd + "listaddressgroupings"
    d = execute_cmd(tmp_cmd)
    # print('output:', d)
    d = re.sub('[, [\]\n]', '', d)
    # print('去掉， \\\\n', d)
    d = d.split('"')
    # print('去掉"', d)
    addresses = []
    num_address = int(len(d) / 4)
    for i in range(num_address):
        addresses.append(d[i * 4 + 1])
    # print("258:",addresses[-1])
    return addresses

def get_address_value(gama, msg, lamda, rest_addresses):
    if len(msg) < 5:
        msg += '0' * (6 - len(msg))
    # 获取符合条件的地址
    address = 0
    all_addresses = rest_addresses

    for i in range(len(all_addresses)):
        #print("272:i=",i,"len=:",len(all_addresses),"len(addr)=",len(all_addresses[i]))
        if all_addresses[i]==RECEIVE_CHANGE_ADDRESS or len(all_addresses[i])!=34:
            continue
        address_last5 = encryption.hex2bin(encryption.address_to_P2SH(all_addresses[i]))[-5:]
        # print(msg[:5])
        if msg[:5] == address_last5:
            address = all_addresses[i]
            break
    """if(address==0):
        print("address=0 and msg=",msg[:5])
        for i in range(len(rest_addresses)):
            address_last5 = encryption.hex2bin(encryption.address_to_P2SH(rest_addresses[i]))[-5:]
            # print(msg[:5])
            if msg[:5] == address_last5:
                print("find")"""

    # 构造合适的value
    value = create_value(msg[5:], gama)
    return address, value

# 选择正确的地址， 计算出value的大小， 进化γ后并返回，其中msg前5位存储到地址中
# 返回值为，新的γ，找到的address，计算好的value
# 若剩余msg不足5位，则末位补0至5位，找到对应的address
def select_address_value(gama, msg, lamda, rest_addresses):
    print('msg:', msg)  # 这里的msg为每一对AV需要处理的信息
    if len(msg) < 5:
        print("msg补零")
        msg += '0' * (6 - len(msg))
    # 获取符合条件的地址
    address = 0
    all_addresses = rest_addresses
    print('rest_addresses:', rest_addresses)
    for i in range(len(all_addresses)):
        address_last5 = encryption.hex2bin(encryption.address_to_P2SH(all_addresses[i]))[-5:]
        # print(msg[:5])
        if msg[:5] == address_last5:
            address = all_addresses[i]
            break
    # 构造合适的value
    value = create_value(msg[5:], gama)
    return address, value


# 选择当前钱数最多的多个地址的txid并使得选择的txid的总钱数大于需要的value值
# 返回TXID和address列表
# TXID：[(txid,vout),(txid,vout)]
# addresses [address1,address2...]
def select_txid(value_sum, address):
    # 获得钱数最多的地址
    print("value_sum=", value_sum)
    TX_FEE = 0.001
    value_sum += TX_FEE
    selected_txid = []
    current_sum = 0
    all_txid = ltc_listunspent(address)
    print("all_txid:", all_txid)
    while current_sum < value_sum and len(all_txid) > 0:
        txid = all_txid.pop(0)
        selected_txid.append((txid[0], txid[1][0]))
        current_sum += txid[1][1]
    if len(all_txid) == 0 and current_sum < value_sum:
        print("out of value%%%%%%%%%%%%%%%%%%%%%%%%%55")
        return None, None
    change = current_sum - value_sum  # 找零
    if change < 0.001:
        change = 0
    return selected_txid, change


# 根据信息生成交易单并返回剩余字符串和交易单ID以及最新的γ，λ
# msg_shad为隐藏信息, _from_label为发送者label，_to_label为发送者的label
# gama，lamda是两个list，分别存储 start和end
# my version: 如果当前所有账户中的货币总额不够，就挖矿
# 返回值是rest_msg, new_gama, rawtx, addr

def mine(address):
    ltc_generatetoaddress(500, address)


def ltc_select_UTXO(value_sum):
    label = ''
    flag = 0
    TXID = list()
    tmp_value = 0
    valid_address = 0

    addresses = get_LTC_account_addresses(label)
    addresses = list(addresses.keys())
    for addr in addresses:
        TXID = list()
        tmp_value = 0
        flag = 0
        print(addr)
        #返回值有问题
        all_txid = ltc_listunspent(1, 99999, addr)  # 返回字典{txid:{UTXO描述字典}，txid:{对应UTXO字典}，……}
        #print("all_txid:", all_txid)
        keys = list(all_txid.keys())
        #print("keys:",keys)
        for txid in keys:
            TXID.append({'txid': txid, 'vout': all_txid[txid]['vout']})  # 该地址拥有的金额总数满足条件的所有tx
            if len(TXID) > 75:
                flag = 2
                break
            value = float(all_txid[txid]['amount'])
            tmp_value += value
            #print("addr:%s tmp_value:%s" % (addr, tmp_value))
            if tmp_value > value_sum:
                valid_address = addr
                flag = 1
                break
        if flag == 1:
            break
        elif flag == 2:
            continue
    print(TXID)
    if flag == 0:
        ex = Exception("没有满足UTXO余额的和大于value_sum的地址")
        raise ex
    else:
        return TXID, valid_address, tmp_value


# send_addr中一定有足够的钱，如果钱不够就提醒用户
def create_one_transaction(msg_shad, gama, lamda, send_addr):
    print("create_one_transaction:len(msg_shad)=", len(msg_shad))
    MIN_INFO_NUM = 8  # 每个value中隐藏信息与address中隐藏信息之和的最小值
    MAX_INFO_NUM = 12
    ADDRESS_INFO_NUM = 5  # 每个地址中隐藏信息的大小
    MAX_VALUE_NUM = 30  # address, value对的最大数量
    MIN_VALUE_NUM_RDM = 20  # value, address对数量随机时的最小值
    ADDRESSES_VALUE = list()
    msg_block = list()  # 存储每个AV对存储的信息数量
    sum_num = 0
    block_num = 0  # value, address对的实际使用量
    value_sum = 0  # 总共需要花费的value数量
    msg_shd_all = ''

    # 计算30个address，value对是否足够容纳该msg
    for i in range(MAX_VALUE_NUM):
        block_size = random.randint(MIN_INFO_NUM, MAX_INFO_NUM)
        msg_block.append(block_size)
        sum_num += block_size
    if sum_num >= len(msg_shad):
        block_num = MAX_VALUE_NUM
    else:
        block_num = random.randint(MIN_VALUE_NUM_RDM, MAX_VALUE_NUM)

    # 开始生成交易单
    msg_tmp = msg_shad
    # print('block_num:', block_num)
    rest_addresses = get_addresses()  # 存储当前剩余可选的addresses
    # print("create one transaction",file=fp)
    for i in range(block_num):
        # 若剩余字符为空则跳出循环
        # 若剩余字符数量小于下一个AV对存储的数量则将下一个AV对存储的字符数量设置为字符剩余数量
        # 若当前剩余字符数量足够多则下一个AV对的存储数量为随机生成的存储数量
        if msg_shad == '':
            # print("msg_shad is empty")
            break
        elif len(msg_shad) < msg_block[i]:
            msg_tmp = msg_shad
        else:
            msg_tmp = msg_shad[:msg_block[i]]

        address_tmp, value_tmp = select_address_value(gama, msg_tmp, lamda, rest_addresses, send_addr)  # 找合适AV对
        if address_tmp == 0:  # 找不到可用地址，构造下一个交易单
            print("no available address")
            break
        rest_addresses.remove(address_tmp)
        gama = encryption.create_gama(gama, lamda)
        ADDRESSES_VALUE.append((address_tmp, value_tmp))
        print(address_tmp, ":", value_tmp, file=fp)
        print("506msg_tmp=", msg_tmp, file=fp)
        msg_shd_all += msg_tmp
        msg_shad = msg_shad[len(msg_tmp):]
        value_sum += float(value_tmp)

    TXID, change = select_txid(value_sum, send_addr)  # 挑选属于send_addrd的utxo，如果钱不够返回None
    while TXID == None:  # 如果send_addr的钱不够就挖矿
        mine(send_addr)
        TXID, change = select_txid(value_sum, send_addr)
        # return create_one_transaction(msg_shad, gama, lamda,send_addr)
    if change > 0:
        print(send_addr, ":", change, file=fp)
        ADDRESSES_VALUE.append((send_addr, change))

    print("end of a transaction", file=fp)

    print("TXID:", TXID)
    print("ADDRESS_VALUE:", ADDRESSES_VALUE)
    rawtx = ltc_createrawtransaction(TXID,ADDRESSES_VALUE)

    test.write_file('ltc_log.txt', 'hidden_message_segment:' + msg_shd_all)
    print("rawtx:", rawtx)
    new_gama = gama
    rest_msg = msg_shad
    return rest_msg, new_gama, rawtx


def get_addr_tail(addr, n):
    address_lastn = encryption.hex2bin(encryption.address_to_P2SH(addr))[-n:]
    return address_lastn


# 返回加密的密钥，输入为需要发送的真实信息与虚假信息，真实信息与虚假信息的字数相等
def calculate_key(message, mask_message):
    key = [0] * len(message)
    for i in range(len(message)):
        key[i] = ord(message[i]) ^ ord(mask_message[i])
    return key


# text为发送信息
# key为加密密钥，共包含五个密钥，分别为AES加密密钥，λ_start,λ_end,γ0_start,γ0_end
# key是一个包含5个元素的列表 key = [AES_key, λ_start,λ_end,γ0_start,γ0_end]


# 生成地址，直到所有地址的后m位的种类数达到n类
def generate_n_addr(m, n):
    while 1:
        all_addresses = get_addresses()
        print(all_addresses)
        all_lastm = list()
        flag = 0
        for i in range(len(all_addresses)):
            lastm = encryption.hex2bin(encryption.address_to_P2SH(all_addresses[i]))[-m:]
            if lastm not in all_lastm:
                all_lastm.append(lastm)
                if len(all_lastm) >= n:
                    flag = 1
                    break
        all_lastm.sort()
        print(all_lastm)
        if flag == 1:
            break
        else:
            new_addr = ltc_getnewaddress('""')
            ltc_generatetoaddress(10, new_addr)
            print("新生成的地址为：", new_addr)




def decode_tx(keys, txid):
    print("decode_tx")
    DEC_NUM = 8
    [AES_key, lamda_start, lamda_end, gama_start, gama_end] = keys
    ADDR_LAST = 5
    AV, sender_pubkeys = get_AV_from_hex(get_transaction(txid)['hex'])
    msg_shd = ''
    print("get_transaction:", get_transaction(txid), file=fp)
    print("AV of one transaction:", file=fp)
    print("len(sender)=", len(sender_pubkeys))
    print("len(AV)=", len(AV))
    print("sender:", sender_pubkeys)
    print("AV:", AV)
    for address_value in AV:
        address = address_value[0]
        if address in sender_pubkeys:
            continue
        value = address_value[1]
        value = int(round((10 ** DEC_NUM) * value))
        value_str = bin(value)[2:]
        # print("value_str=",value_str)
        # print("gama_start=",gama_start)
        try:
            value_valid = encryption.find_valid_str(value_str, gama_start, gama_end)
        except:
            return None, None, None
        lastn = get_addr_tail(address, ADDR_LAST)
        msg_shd += lastn + value_valid
        print("640msg_shd:lastn+value_valid:", lastn + value_valid)
        [gama_start, gama_end] = encryption.create_gama([gama_start, gama_end], [lamda_start, lamda_end])
    print("txid:" + txid)
    print("msg:" + msg_shd)
    return msg_shd, gama_start, gama_end


def receive_message(keys, txid_list):
    msg_shd = ''
    for txid in txid_list:
        msg_shd_tmp, gama_start, gama_end = decode_tx(keys, txid)
        if msg_shd_tmp == None:
            return None
        order = ORDER_STAMP.index(msg_shd_tmp[:5])
        print("order:", order)
        msg_shd = msg_shd + msg_shd_tmp[5:]
        keys[3] = gama_start
        keys[4] = gama_end
    print("msg_shd:", msg_shd)
    msg_shd = encryption.sub_0tail(msg_shd)
    # keys = [AES_key, lamda_start, lamda_end, gama_start, gama_end]
    try:
        msg_encrypted = encryption.find_valid_str(msg_shd, keys[1], keys[2])
    except:
        return None
    print('msg_shd_decode:', msg_shd)
    print('msg_encrypted:', msg_encrypted)
    msg = encryption.AES_decrypt(encryption.bin2hex(msg_encrypted).encode(), keys[0])
    return msg


def ltc_receive_message2(keys, txid_list):
    msg_shd = ''
    for txid in txid_list:
        msg_shd_tmp, gama_start, gama_end = decode_tx(keys, txid)
        if msg_shd_tmp == None:
            return None
        order = ORDER_STAMP.index(msg_shd_tmp[:5])
        print("order:", order)
        msg_shd = msg_shd + msg_shd_tmp[5:]
        keys[3] = gama_start
        keys[4] = gama_end
    print("msg_shd:", msg_shd)
    msg_shd = encryption.sub_0tail(msg_shd)
    # keys = [AES_key, lamda_start, lamda_end, gama_start, gama_end]
    try:
        msg_encrypted = encryption.find_valid_str(msg_shd, keys[1], keys[2])
    except:
        return None
    return msg_encrypted


def get_addressesbyaccount(account):
    cmd = fix_cmd + "getaddressesbyaccount " + '"' + account + '"'
    print("cmd:", cmd)
    result = execute_cmd(cmd)
    return eval(result)


def account_exist(account):
    result = get_addressesbyaccount(account)
    return len(result) > 0


def listaddressgroupings():
    tmp_cmd = fix_cmd + "listaddressgroupings"
    # print("cmd:", tmp_cmd)
    result = execute_cmd(tmp_cmd)
    # print("671:",result)
    result = eval(result)
    return result


def get_LTC_account_address(label):
    result = {}
    addressesgroupings = listaddressgroupings()
    for group in addressesgroupings:
        if group[0][2] == label:
            result[group[0][0]] = group[0][1]
    # result=result[account]
    return result


def add_LTC_account_address(account):
    cmd = fix_cmd + 'getnewaddress ' + '"' + account + '"'
    result = execute_cmd(cmd)
    return result


def getreceivedbyaddress(address):
    cmd = fix_cmd + 'getreceivedbyaddress ' + '"' + address + '"'
    result = execute_cmd(cmd)
    result = eval(result)
    return result


def select_addr_txid(address, value_sum):
    # 获取该地址的txid，直到满足总的钱数大于所需的钱数
    tmp_cmd = fix_cmd + "listaddressgroupings"
    result = execute_cmd(tmp_cmd)
    result = eval(result)
    result = {result[i][0][0]: result[i][0][1] for i in range(len(result))}
    print("result:", result)

    value = result[address]

    if value < value_sum:
        print("value:", value)
        print("value_sum:", value_sum)
        return False
    tmp_value = 0  # 当前的txid的总钱数
    all_txid = ltc_listunspent(1,99999,address)
    print("all_txid:", all_txid)
    TXID = list()  # 返回的txid：vout对
    for txid in all_txid:
        TXID.append((txid[0], txid[1][0]))
        tmp_value += float(txid[1][1])
        if tmp_value > value_sum:
            return TXID, tmp_value


def ltc_select_addr_txid(address, value_sum):
    # 获取该地址的txid，直到满足总的钱数大于所需的钱数
    tmp_value = 0  # 当前的txid的总钱数
    all_txid = ltc_listunspent(1, 99999, address)
    keys = list(all_txid.keys())
    TXID = list()  # 返回的txid：vout对
    for txid in keys:
        TXID.append({'txid': txid, 'vout': all_txid[txid]['vout']})
        tmp_value += float(all_txid[txid]['amount'])
        print("tmp_value:", tmp_value)
        if tmp_value > value_sum:
            print("sum_value:", tmp_value)
            return TXID, tmp_value
    return False, 0


# 输入信息：发送地址from_address, 接收地址to_address, 发送金额value
# 输出信息：若交易成功返回交易hash，交易时间；若失败返回报错信息（如xx输入不满足要求）
def ui_transfer_litecoin(from_address, to_address, value):
    '''
    result = select_addr_txid(from_address, value)
    print("653result:", result)
    TXID, total_value = result
    print("653")
    if not TXID:
        errorinfo = "余额不足或发送地址错误"
        return errorinfo
    ADDRESSES_VALUE = [(to_address, value)]
    change = total_value - value - 0.001;
    if change > 0:
        ADDRESSES_VALUE.append((from_address, change))
    print("txid:", TXID)
    out = ltc_createrawtransaction(TXID, ADDRESSES_VALUE)
    if not out:
        errorinfo = "接受地址错误"
        return errorinfo
    txid = out
    pri_key = ltc_dumpprivkey(from_address)
    print('pri_key:', pri_key)
    signed_hex = ltc_sign_withkey(txid, [pri_key])
    txid = ltc_sendrawtransaction(signed_hex).replace('\n', '')
    ltc_generatetoaddress(10, from_address)
    return txid
    '''
    TXID, sum_value = ltc_select_addr_txid(from_address, value)
    if not TXID:
        errorinfo = "余额不足或发送地址错误"
        return errorinfo
    if sum_value - value > 0.0001:  # 设置找零
        check = sum_value - value - 0.0001
        check = format(check, '.8f')
        print("sum_value: %s \n value: %s\n check:%s " % (sum_value, value, check))
        ADDRESSES_VALUE = [{'address': to_address, 'value': value}, {'address': from_address, 'value': check}]
    else:
        ADDRESSES_VALUE = [{'address': to_address, 'value': value}]
    out = ltc_createrawtransaction(TXID, ADDRESSES_VALUE)  # 返回生成的未签名交易的序列化字符串
    if not out:
        errorinfo = "接受地址错误"
        return errorinfo
    txid = out
    pri_key = ltc_dumpprivkey(from_address)
    signed_hex = ltc_sign_withkey(txid, pri_key)
    ret = ltc_sendrawtransaction(signed_hex)
    ret = ret.replace('\n', '')
    return ret




# 返回值key是用字符串表示的int型数组
def create_key(real_message, false_message):  # 如果real_message的长度大于false_message，就用空格来补充
    if len(real_message) > len(false_message):
        false_message += ' ' * (len(real_message) - len(false_message))
    key = [ord(real_message[i]) ^ ord(false_message[i]) for i in range(len(real_message))]
    return str(key)


# key是用字符串表示的int型数组
def decode_realmessage(key, false_message):
    key = eval(key)
    if len(key) > len(false_message):
        false_message += ' ' * (len(key) - len(false_message))
    real_message = ''
    for i in range(len(key)):
        real_message += chr(key[i] ^ ord(false_message[i]))
    return real_message


def get_false_message():
    false_message_file = 'false_message.txt'
    with open(false_message_file, 'r', encoding='utf-8') as fp:
        false_messages = fp.readlines()
    index = random.randint(0, len(false_messages) - 1)
    return false_messages[index].strip()


def calculate_hash(address, seed):
    address_bytes = base58.b58decode(address)
    address_hex = binascii.hexlify(address_bytes)
    address_int = int(address_hex, 16)
    value_int = address_int * seed
    value_bytes = encryption.int_to_bytes(value_int)
    return hashlib.sha256(value_bytes).hexdigest()


def ltc_listreceivedbyaddress():
    cmd = fix_cmd + "listreceivedbyaddress"
    result = execute_cmd(cmd)
    print('reasult:', result)
    result = eval(result)
    return result


# 当确定和某个人建立隐匿信道，需要输入seed和规则，调用generate_satisfied_address生成一个地址？
# 发送者角度：输入一个有足够钱的地址，seed，规则，信息
# 接收者角度：输入seed，规则，扫描所有的交易单，验证交易单与seed哈希后满足规则就解析交易单
# 有没有必要规定每天只能发一条信息？只能接收当天发送的信息？

# 根据日期限制，seed和规则找出所有的交易单：
def is_valid_address(address, seed, rule):
    result = calculate_hash(address, seed)
    if result[-10:] == rule:
        return True
    return False


def is_valid_txid(txid, seed, rule):
    time, sender, order = get_time_sender_order(txid)
    if time <= LAST_TIME:
        return False, None, None
    for address in sender:
        if is_valid_address(address, seed, rule):
            return True, time, order
    return False, None, None


def find_txids(seed, rule):
    """
    transaction_list = ltc_listreceivedbyaddress()
    txid_list = []
    for item in transaction_list:
        txid_list.extend(item["txids"])
    txid_list = list(set(txid_list))
    """
    txid_list = ['60f6f7598cee6d80dff1bff5f0aec0b2e88bfa3a0820e87dbce4fc9f1d1f816a',
                 'bcd7857d8f5b647d51d945f83d97f5d98b8a7a899fa385da2144d04590079e22',
                 '4ecd53002acfa1c9213f5c69c5f439b880de3071b7b34b3d934f5cbe780ebf0c',
                 '135a50991751ca389826d288f56924858900b154cfa97ad271a0c898c657d034',
                 '14ccc540206e5b1847b53b731ed3a28952e6418a54c9c08ed28f98ff9b74b5d2',
                 'e054aa751d2a0843327c5802882ee6e2cb852f98f555be47af2abb4a431fdac5',
                 '397c71414448cb54f89f7f2b3a39411b602fd26ceefeabc7558c26460f32afe0',
                 '55b7089389350cff21642b918cffbb4445ad3e1dfbc28d3341a6ef14e5fa267b',
                 '16277a9425ad8865db8bc7ccde9ad50b7db80108073ed7768b7aaf61879c75d7',
                 'dc5e965b8d86083904c2b286628479b1c6e4cdf847163fcb28f426989d495324',
                 'f18b53e4a9cb893a6b87a1f4021c3d3c3c42a15fbae931773824412699bdbc18',
                 'b491e2e8e3620c2ab519ca8deb454f057d20eaa1276d173d3da417006e69d303',
                 'd48ca67d2a9f2f8ac038079930711a762347edb567273c38bf735cd41aa1b901',
                 'de73e6c5c37f3131b15d7af6a30d6655aeaca3cbc6c9f8df33c26a195efd4dd8',
                 '526813cf77b4820043f813fb04fb4f26d9a29494cbd7a69f6865ff919600b824',
                 'bc52ab6d396f019bbd219523c03245c8f14d0b6f19b9670072718b32d76212c6',
                 '03861ef49fdc04a14f8551188a5f646501f62dd2596714b503a415305d020786',
                 'edc96bf739156ada3dedd282417a5812f76f94fc39bd609b8de6c304ae0cd724',
                 'b67bbcc81ecd956814fd1e16de00881e88f075a8a6ec6575ad45f545a0e2f838',
                 '30cc84d4a84a7f0c7a14ea699aca10d5d6d07e0af195f42fa15782d4f9e58cab',
                 'c20d6dd5e967e77a8d75ebe60db9c76299a1d1abb77d15364a3e16501e6f4226',
                 '56079daa256e3fe53569e693cfd46bda34516b28305ebf9d1f7597281b3d984e',
                 'f644c4cfc2618a126c4348335bb05665b8bf38ce88660fea3ee31da8da75bd6a',
                 '4893e89102d309ad2e9ac17eac2d0188cc6ef6d84deb1e413b70ad8d2eed1a7f',
                 'cb05ac02349ba28693d3309f99cce9b7460b68fc3cf303b12f7d250ccff5b672',
                 'b84709df5f75aac71ad19953115aee4cb9617a4ab66e7314f0d4d7bfe0bee882',
                 '5bd3531b3122dbe96f35014966a91bb391f3f9ff45a76b2cbc35f867a6fa5af3',
                 '62f377bf956b156d8fdf5ff8ac2c282a5f7bcd419f29246c5ac004762b6e48fb',
                 '696443fb263b0ddb9255a6ed3635a7fb5be862429b0f772c582fd22190c7a6c3',
                 '14d3007334960800ce2a6f31e96b0f0e77083780b07d27f1a179c9f852577f51',
                 '6095ad3594754ad1c06b25b95855339996171134924a8e7b443b0049519cb697']

    valid_txids = []
    global LAST_TIME
    nearest_time=LAST_TIME
    for txid in txid_list:
        is_valid, time, order = is_valid_txid(txid, seed, rule)
        if time>nearest_time:
            nearest_time=time
        if is_valid:
            print((time, txid, order))
            valid_txids.append((time, txid, order))
    LAST_TIME=nearest_time
    return valid_txids


def group_txids(sorted_txids):
    index = 0
    groups = []
    txids = []
    while len(sorted_txids) >= 0:
        if len(sorted_txids) == 0:
            if len(txids) > 0:
                groups.append(txids)
            break
        time, txid, order = sorted_txids.pop(0)
        if order == 0 and len(txids) > 0:
            groups.append(txids)
            txids = [txid]
            index = 1
        elif order == index:
            txids.append(txid)
            index += 1

    return groups


def find_message(keys, seed, rule):
    valid_txids = find_txids(seed, rule)
    if len(valid_txids) == 0:
        return False, None
    sorted_txids = sorted(valid_txids, key=lambda x: x[0])
    sorted_txids = group_txids(sorted_txids)
    messages = []
    for txid_list in sorted_txids:
        # print(txid_list)
        message = receive_message(keys, txid_list)
        if message != None:
            messages.append(message+'\n')
    return messages


def get_AV_fromtx(tx):
    AV = list()
    tmp_value = 0

    tx = re.sub('[, [\]\n{}:]', '', tx)
    # print(tx)
    tx_split = tx.split('"')#以空格分隔
    # print(tx_split)
    for i in range(len(tx_split)):
        if tx_split[i] == 'value':
            tmp_value = tx_split[i + 1]
        elif tx_split[i] == 'addresses':
            AV.append({'address': tx_split[i + 2], 'value': tmp_value})
    return AV


def send_message(text, key, address):
    AES_key = key[0]
    text_encrypt = encryption.AES_encrypt(text, AES_key).decode()
    text_bin = encryption.hex2bin(text_encrypt)
    # print("text_encrypt_bin:", text_encrypt)
    lamda = [key[1], key[2]]
    text_shadow = create_shadow_msg(text_bin, lamda)  # 转换为 rdm_str + λ_start + C + λ_end + rdm_str
    tmp_msg = text_shadow
    gama = [key[3], key[4]]
    TXID = list()
    # 直到消息传递完成
    # 生成交易单,签名发送，并返回剩下的信息tmp_msg,新的γ, 交易单的ID
    privateKey = ltc_dumpprivkey(address)
    order = 0
    while tmp_msg != '':
        print(len(tmp_msg))
        print("tmp_msp%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%5" + tmp_msg)
        tmp_msg = ORDER_STAMP[order] + tmp_msg
        tmp_msg, gama, rawtx = create_one_transaction(tmp_msg, gama, lamda, address)
        order += 1
        signed_tx = ltc_sign_withkey(rawtx, [privateKey])
        txid = ltc_sendrawtransaction(signed_tx)
        TXID.append(txid.strip())
    return TXID


def ltc_send_message2(text, key):
    seed = 5
    rule = "9ac7893916"
    address = generate_satisfied_address(seed, rule)
    lamda = [key[1], key[2]]
    text_shadow = create_shadow_msg(text, lamda)  # 转换为 rdm_str + λ_start + C + λ_end + rdm_str
    tmp_msg = text_shadow
    gama = [key[3], key[4]]
    TXID = list()
    # 直到消息传递完成
    # 生成交易单,签名发送，并返回剩下的信息tmp_msg,新的γ, 交易单的ID
    privateKey = ltc_dumpprivkey(address)
    order = 0
    while tmp_msg != '':
        # print(len(tmp_msg))
        print("tmp_msp:" + tmp_msg)
        tmp_msg = ORDER_STAMP[order] + tmp_msg
        tmp_msg, gama, rawtx = create_one_transaction(tmp_msg, gama, lamda, address)
        order += 1
        signed_tx = ltc_sign_withkey(rawtx, [privateKey])
        txid = ltc_sendrawtransaction(signed_tx)
        txid = txid.strip()
        print("send_txid:", txid)
        signed_hex = get_transaction(txid)['hex']
        print("signed_hex:", signed_hex)
        decode = ltc_decoderawtransaction(signed_hex)
        print("tx_decode:", decode)
        test.write_file('ltc_log.txt', decode)
        TXID.append(txid.strip())
    return TXID





def send(text):
    seed = 5
    rule = "9ac7893916"
    AES_key = '9bbd25ae87d9933b'
    lamda_start = '10111111101010011'
    lamda_end = '00001110001011101'
    gama_start = '110'
    gama_end = '101'
    keys = [AES_key, lamda_start, lamda_end, gama_start, gama_end]
    address=generate_satisfied_address(seed, rule)
    print("litecoin-client.send",send_message(text,keys,address))

def receive(seed,rule):
    seed = 5
    rule = "9ac7893916"
    AES_key = '9bbd25ae87d9933b'
    lamda_start = '10111111101010011'
    lamda_end = '00001110001011101'
    gama_start = '110'
    gama_end = '101'
    keys = [AES_key, lamda_start, lamda_end, gama_start, gama_end]
    return find_message(keys,seed,rule)


def ltc_receive_message(key, txid):
    ADDR_LAST = 5  # 采用的addr后的位数
    [AES_key, lamda_start, lamda_end, gama_start, gama_end] = key
    msg_shd = ''
    all_AV = list()
    for i in range(len(txid)):
        # print(signed_hex[i])
        signed_hex = ltc_getrawtransaction(txid[i]).replace('\n', '')
        tx = ltc_decoderawtransaction(signed_hex)  # 交易的json对象
        AV = get_AV_fromtx(tx)
        #AV = get_AV_from_hex(signed_hex)
        all_AV += AV
    print(all_AV)
    for i in range(len(all_AV)):
        if all_AV[i]['address'] == RECEIVE_CHANGE_ADDRESS:
            continue
        lastn = get_addr_tail(all_AV[i]['address'], ADDR_LAST)#msg的前五位
        print('lastn:', lastn)
        value_int = encryption.float2int(all_AV[i]['value'])#先转换成int再转换为bin二进制
        print('value_int:', value_int)
        value_str = bin(int(value_int))[2:]
        print('value_str:', value_str)
        value_valid = encryption.find_valid_str(value_str, gama_start, gama_end)#提取出msg_shad
        msg_shd += lastn + value_valid
        [gama_start, gama_end] = encryption.create_gama([gama_start, gama_end], [lamda_start, lamda_end])#未实现
    print(msg_shd)
    msg_shd = encryption.sub_0tail(msg_shd)#去掉msg_shd末尾的0
    msg_encrypted = encryption.find_valid_str(msg_shd, lamda_start, lamda_end)
    print('msg_shd_decode:', msg_shd)
    print('msg_encrypted:', msg_encrypted)
    msg = encryption.AES_decrypt(encryption.bin2hex(msg_encrypted).encode(), AES_key)
    return msg


def ltc_execute_cmd2(cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.load_system_host_keys()
    client.connect("192.168.56.101", port=22, username="peiqianman", password='123')
    stdin, stdout, stderr = client.exec_command("cd Documents/litecoin/litecoin-0.18.1;" + cmd)
    output = stdout.read()
    error = stderr.read()
    if error:
        ex = Exception("命令行运行错误，错误为：\n" + error.decode() + "\n运行的命令行为: " + str(cmd))
        raise ex
    client.close()
    return output.decode()


def ui_send_ltctx(db_name, fromaddr, toaddr, amount):
    oplist, value = get_unspent(fromaddr)
    if value == 0:
        raise Exception("insufficent balance!")
    tmp_cmd = fix_cmd2 + 'createrawtransaction "['

    for i in range(len(oplist)):
        tmp_cmd = tmp_cmd + '{\\"txid\\":\\"%s\\",\\"vout\\":%s},' % (oplist[i].txid, oplist[i].vout)
    tmp_cmd = tmp_cmd[:-1] + ']\" \"{'
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (toaddr, amount)
    change_amount = Decimal(str(value)) - Decimal(str(amount)) - Decimal('0.001')
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (fromaddr, change_amount)
    tmp_cmd = tmp_cmd[:-1] + '}"'
    raw_hex = ltc_execute_cmd2(tmp_cmd)
    sk_b_special = DB_select.get_skb_by_selfaddr(db_name, fromaddr, 'litecoin')
    sk_b_self = DB_select.get_skb_by_selfaddr(db_name, fromaddr, 'litecoin')
    sk_b = sk_b_self or sk_b_special
    if sk_b:
        wif_sk = crypto.get_wifsk(sk_b)
        wif_sk_str = wif_sk.decode("utf-8")
        signed_hex = ltc_sign_withkey(raw_hex, wif_sk_str)
        txid = ltc_sendrawtransaction(signed_hex)
        return txid
    else:
        raise Exception("no skb,createtx failed!")


def validate_address(address):
    cmd = fix_cmd2+"validateaddress "+address
    ret = ltc_execute_cmd2(cmd)
    ret_json = json.loads(ret)
    isvalid = ret_json['isvalid']
    return isvalid


def ltc_importaddress(address, label):
    tmp_cmd = fix_cmd2 + " importaddress " + address + " " + label
    return ltc_execute_cmd2(tmp_cmd)


def getall_address_balance(account):
    # listreceivedbyaddress just helps find the address with given label
    cmd = fix_cmd2+"listreceivedbyaddress 0 true true"
    ret = ltc_execute_cmd2(cmd)
    list_ret = json.loads(ret)
    ret_dict = dict()
    for i in range(len(list_ret)):
        if list_ret[i]['label'] == account:
            addr = list_ret[i]['address']
            #amount = list_ret[i]['amount']
            oplist, amount = get_unspent(addr)
            ret_dict[addr] = amount
    return ret_dict


def ltc_generatenewaddress():
    sk, pk = crypto.gen_keypair()
    pk_bytes, sk_bytes = crypto.get_byteskeypair(pk, sk)
    address = crypto.gen_address(pk, 'testnet', 'litecoin')
    pk_script = crypto.get_ltc_pkscript(pk, 'testnet')
    find = DB_select.check_pkscript(pk_script)
    if not find:
        DB_insert.addr_insert(pk_script, pk_bytes, sk_bytes, 'litecoin')
    else:
        raise Exception("the address already exsits")
    ltc_importaddress(address)
    return address


def ltc_listunspent2(account):
    tmp_cmd = fix_cmd2 + " listunspent 0 99999 [\\\"" + account + "\\\"]"
    UTXO_PARA_num = 10  # 一个UTXO中的参数个数
    UTXO = ltc_execute_cmd2(tmp_cmd)
    UTXO = re.sub('[, :{}[\]\n]', '', UTXO)
    #print(UTXO)
    UTXO = UTXO.replace('""', '"')
    # print(UTXO)
    UTXO = UTXO[1:].split('"')
    UTXO_num = int(len(UTXO) / (UTXO_PARA_num * 2))
    ret = dict()
    for i in range(UTXO_num):
        start_index = i * UTXO_PARA_num * 2  # 在UTXO中txid这个字符串所在的位置索引
        ret[UTXO[start_index + 1]] = dict()
        for j in range(int(UTXO_PARA_num - 1)):
            ret[UTXO[start_index + 1]][UTXO[start_index + 2 + j * 2]] = UTXO[start_index + 3 + j * 2]
            # print(i * UTXO_PARA_num + 2 + j * 2, i * UTXO_PARA_num + 3 + j * 2)
    return ret


def get_unspent(address):
    tmp_value = 0  # 当前的txid的总钱数
    all_txid = ltc_listunspent2(address)
    keys = list(all_txid.keys())
    Outpoint = namedtuple('Outpoint', ['txid', 'vout'])
    oplist = list()
    for txid in keys:
        outpoint = Outpoint(txid, int(all_txid[txid]['vout']))
        oplist.append(outpoint)
        tmp_value += Decimal(all_txid[txid]['amount'])
        if tmp_value == tmp_value.to_integral():
            tmp_value = tmp_value.to_integral()
        else:
            tmp_value=tmp_value.normalize()
    tmp_value = format(float(tmp_value), '.3f')
    return oplist, tmp_value


def ltc_listsinceblock(since_block):
    tmp_cmd = fix_cmd2 + "getblockhash " + str(since_block)
    block_hash = ltc_execute_cmd2(tmp_cmd)  # the rpc return result has an extra null str
    tmp_cmd = fix_cmd2+"listsinceblock " + block_hash.strip() + " 1 true"
    ret = ltc_execute_cmd2(tmp_cmd)
    ret_json = json.loads(ret)
    return ret_json


def get_sender_txid(addr, block_since):
    #listfrom = 0
    txid_list = list()
    ret_json = ltc_listsinceblock(block_since)
    #print(ret_json)
    tx_list = ret_json['transactions']
    for i in range(len(tx_list)):
        if tx_list[i].get('address') == addr and tx_list[i]['category'] == 'send':
            txid_list.append(tx_list[i]['txid'])
    return txid_list


def ltc_sendrawtx(tx):
    tx_hex = serialize.tobuf_tx(tx).hex()
    tmp_cmd = fix_cmd2 + "sendrawtransaction " + tx_hex
    return ltc_execute_cmd2(tmp_cmd)


def ltc_getblockcount():
    tmp_cmd = fix_cmd2+"getblockcount"
    blocknum_str = ltc_execute_cmd2(tmp_cmd)
    return int(blocknum_str)


def ltc_gettransaction_detail(txid):
    tmp_cmd = fix_cmd2 + "getrawtransaction " + txid +" true"
    ret_json = json.loads(ltc_execute_cmd2(tmp_cmd))
    return ret_json


def ui_send_ltctx(db_name, fromaddr, toaddr, amount):
    oplist, value = get_unspent(fromaddr)
    if value == 0:
        raise Exception("insufficent balance!")
    tmp_cmd = fix_cmd2 + 'createrawtransaction "['

    for i in range(len(oplist)):
        tmp_cmd = tmp_cmd + '{\\"txid\\":\\"%s\\",\\"vout\\":%s},' % (oplist[i].txid, oplist[i].vout)
    tmp_cmd = tmp_cmd[:-1] + ']\" \"{'
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (toaddr, amount)
    change_amount = Decimal(str(value)) - Decimal(str(amount)) - Decimal('0.001')
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (fromaddr, change_amount)
    tmp_cmd = tmp_cmd[:-1] + '}"'
    raw_hex = ltc_execute_cmd2(tmp_cmd)
    sk_b = DB_select.get_user_skb(db_name,fromaddr,'litecoin')
    if sk_b:
        wif_sk = crypto.get_wifsk(sk_b)
        wif_sk_str = wif_sk.decode("utf-8")
        signed_hex = ltc_sign_withkey(raw_hex, wif_sk_str)
        txid = ltc_sendrawtransaction(signed_hex)
        return txid
    else:
        raise Exception("no skb,createtx failed!")
# --------同步--------
def get_vin_pk(txid):
    tx_detail = ltc_gettransaction_detail(txid)
    vin_list = tx_detail['vin']
    vin = vin_list[0]
    script_sig = vin['scriptSig']['asm']
    for i in range(len(script_sig)):
        if script_sig[i] == ']':
            pk_compressed = script_sig[i+2:]
            pk_raw = crypto.recover_pk_fromstr(bytes.fromhex(pk_compressed))
            break
    return pk_raw


def get_sending_txidlist(blocksince):
    txid_list = list()
    ret_json = ltc_listsinceblock(blocksince)
    tx_list = ret_json['transactions']
    for i in range(len(tx_list)):
        if tx_list[i]['category'] == 'send':
            txid = tx_list[i]['txid']
            txid_list.append(txid)
    return txid_list


def get_vout_addrlist(txid):
    addr_list = list()
    tx_detail = ltc_gettransaction_detail(txid)
    vout_list = tx_detail['vout']
    for i in range(len(vout_list)):
        tmp_addr_list = vout_list[i]['scriptPubKey'].get('addresses')
        if not tmp_addr_list:
            continue
        for j in range(len(tmp_addr_list)):
            addr_list.append(tmp_addr_list[j])
    return addr_list


# --------receiver-------
def find_special_pk(block_since, num_zero):
    addr_list = list()
    txid_list = list()
    pk_queue = Queue()  # 可能符合该规则的pk不止一个，都存储起来
    ret_json = ltc_listsinceblock(block_since)
    tx_list = ret_json['transactions']
    for i in range(len(tx_list)):
        if tx_list[i]['category'] == 'send':
            tmp_addr = tx_list[i].get('address')
            if not tmp_addr or tmp_addr in addr_list:
                continue
            tmp_pkhash = crypto.recover_ltc_pkhash(tmp_addr)
            tmp_hash = crypto.hashlib.sha256(tmp_pkhash).digest()
            if tmp_hash.hex()[:num_zero] == '0'*num_zero:
                print("addr:", tmp_addr)
                addr_list.append(tmp_addr)
                txid_list.append(tx_list[i]['txid'])
    print("txid:",txid_list)
    for i in range(len(txid_list)):
        pk_raw = get_vin_pk(txid_list[i])
        pk_queue.put(pk_raw)
    return pk_queue


def receiver_sendtx(address, to_address):
    oplist, value = get_unspent(address)
    tmp_cmd = fix_cmd2 + 'createrawtransaction "['

    for i in range(len(oplist)):
        tmp_cmd = tmp_cmd + '{\\"txid\\":\\"%s\\",\\"vout\\":%s},' % (oplist[i].txid, oplist[i].vout)
    tmp_cmd = tmp_cmd[:-1] + ']\" \"{'

    amount = random.randint(1, 5) * pow(10, -3)
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (to_address, amount)
    change_amount = Decimal(str(value)) - Decimal(str(amount)) - Decimal('0.001')  # change amount
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (address, change_amount)
    tmp_cmd = tmp_cmd[:-1] + '}"'
    raw_hex = ltc_execute_cmd2(tmp_cmd)
    sk_b = DB_select.get_skb_by_msgreceiveraddr(address, 'litecoin')
    if sk_b:
        wif_sk = crypto.get_wifsk(sk_b)
        wif_sk_str = wif_sk.decode("utf-8")
        signed_hex = ltc_sign_withkey(raw_hex, wif_sk_str)
        txid = ltc_sendrawtransaction(signed_hex)
        return txid
    else:
        print("no skb,createtx failed!")


# -----sender------
def sender_send_ltctx(dbname, sender_address, DH_address, amount):
    oplist, value = get_unspent(sender_address)
    if len(oplist) == 0:
        return None
    tmp_cmd = fix_cmd2 + 'createrawtransaction "['

    for i in range(len(oplist)):
        tmp_cmd = tmp_cmd + '{\\"txid\\":\\"%s\\",\\"vout\\":%s},' % (oplist[i].txid, oplist[i].vout)
    tmp_cmd = tmp_cmd[:-1] + ']\" \"{'

    #amount = random.randint(1, 5) * pow(10, -3)
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (DH_address, amount)
    change_amount = Decimal(str(value)) - Decimal(str(amount)) - Decimal('0.001')  # change amount
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (sender_address, change_amount)
    tmp_cmd = tmp_cmd[:-1] + '}"'
    # tmp_cmd = fix_cmd1 + "sendtoaddress " + recieve_addr.strip() + " " + str(amount) + " "+ " \" \"  \" \" true true null \"unset\" null 1.1"
    raw_hex = ltc_execute_cmd2(tmp_cmd)
    sk_b = DB_select.get_user_skb(dbname,sender_address,'litecoin')
    if sk_b:
        wif_sk = crypto.get_wifsk(sk_b)
        wif_sk_str = wif_sk.decode("utf-8")
        signed_hex = ltc_sign_withkey(raw_hex, wif_sk_str)
        txid = ltc_sendrawtransaction(signed_hex)
        return txid
    else:
        print("no skb,createtx failed!")


def get_vin_pk(txid):
    tx_detail = ltc_gettransaction_detail(txid)
    vin_list = tx_detail['vin']
    vin = vin_list[0]
    script_sig = vin['scriptSig']['asm']
    for i in range(len(script_sig)):
        if script_sig[i] == ']':
            pk_compressed = script_sig[i+2:]
            pk_raw = crypto.recover_pk_fromstr(bytes.fromhex(pk_compressed))
            return pk_raw


def mining(address, number):
    tmpcmd = fix_cmd2+"generatetoaddress "+" " + str(number)+" "+address
    txid_list = ltc_execute_cmd2(tmpcmd)
    return txid_list

if __name__ == '__main__':
    '''
    address= "QMAsw7LAfT3Sjn1qRqzcrFiNGZ5PfShGAr"
    AES_key = '9bbd25ae87d9933b'
    lamda_start = '10111111101010011'
    lamda_end = '00001110001011101'
    gama_start = '110'
    gama_end = '101'
    keys = [AES_key, lamda_start, lamda_end, gama_start, gama_end]
    text="明天下午三点邮局见面"
    start=datetime.datetime.now()
    txids=send_message(text,keys,address)
    print("receve message:",receive_message(keys,txids))
    end=datetime.datetime.now()
    print("time:",end-start)
    '''

    addr="n2hZPfHZjj9JBjzWda8AQGiatDuHaRZDyA"
    print(mining(addr,1))