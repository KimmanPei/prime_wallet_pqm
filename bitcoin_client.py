import json
import re
from collections import namedtuple
from queue import Queue

import crypto
import random
import paramiko
import time
import test
import DB_insert
import DB_select
import serialize
from decimal import Decimal


# 比特币客户端bitcoin.exe所在地址
path = "E:\\bitcoin core\\Bitcoin\\daemon"
# bitcoin测试网络运行时的固定指令
fix_cmd = "./bitcoin-cli -regtest "
check_addr = "2MsNBFo2NicvfFhjDruQT4nfCm7UNNSp4mJ"  # 找零地址
# 消息接收方使用钱包1，消息发送方模块使用钱包2，真正发送隐秘消息的模块使用钱包3
fix_cmd1 = "bitcoin-cli  -datadir=/home/peiqianman/.bitcoin1/ -conf=/home/peiqianman/.bitcoin1/bitcoin1.conf  -rpcport=19111 "
fix_cmd2 = "bitcoin-cli  -datadir=/home/peiqianman/.bitcoin2/ -conf=/home/peiqianman/.bitcoin2/bitcoin2.conf  -rpcport=19112 "
fix_cmd3 = "bitcoin-cli  -datadir=/home/peiqianman/.bitcoin3/ -conf=/home/peiqianman/.bitcoin3/bitcoin3.conf  -rpcport=19113 "


def btc_execute_cmd(cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.load_system_host_keys()
    client.connect("192.144.175.67", port=22, username="ubuntu", password='QkDfZWg,52M%=7e')
    stdin, stdout, stderr = client.exec_command("cd bitcoinServer/bitcoin-0.19.0.1/bin;" + cmd)
    output = stdout.read()
    error = stderr.read()
    if error:
        ex = Exception("命令行运行错误，错误为：\n" + error.decode() + "\n运行的命令行为: " + str(cmd))
        raise ex
    client.close()
    return output.decode()


# 创建一个新的地址
def btc_getnewaddress(label):
    tmp_cmd = fix_cmd1 + "getnewaddress " + label
    return btc_execute_cmd2(tmp_cmd)


# 检查地址是否有效
def btc_is_valid_address(address):
    all_addresses = btc_get_addresses()
    if address in all_addresses:
        return True
    else:
        return False


# 挖矿
def btc_generatetoaddress(n_block, address):
    tmp_cmd = fix_cmd + "generatetoaddress " + str(n_block) + ' "' + address + '"'
    return btc_execute_cmd(tmp_cmd)


# 列出当前所有地址及所持比特币及其标签
# 返回一个字典，字典结构为{laber: {address:value,..},..}
def btc_listaddressgroupings_old():
    tmp_cmd = fix_cmd + "listaddressgroupings"
    d = btc_execute_cmd(tmp_cmd)
    # print('output:', d)
    d = re.sub('[, [\]\n]', '', d)
    # print('去掉， \\\\n', d)
    d = d.split('"')
    # print('去掉"', d)
    addresses = dict()
    num_address = int(len(d) / 4) + 1
    for i in range(num_address):
        if d[(i+1) * 4] != "" or i == num_address - 1:
            addresses['null'] = {d[(i+1) * 4 - 3]: d[(i+1) * 4 - 2]}
            d.pop((i+1) * 4 - 3)
            d.pop((i + 1) * 4 - 3)
            break
    d.pop(0)
    for i in range(num_address - 1):
        # print(d[i*4+2])
        # print(list(addresses.keys()))
        # keys = list(addresses.keys())
        if d[i*4+2] in addresses.keys():
            # print("repeat", addresses[d[i*4+2]])
            addresses[d[i*4+2]][d[i*4]] = d[i*4+1]
        else:
            addresses[d[i*4+2]] = {d[i*4]: d[i*4+1]}
        # print(addresses)
    return addresses


# 列出当前所有地址及所持比特币及其标签
# 返回一个字典，字典结构为{laber: {address:value,..},..}
def btc_listaddressgroupings():
    tmp_cmd = fix_cmd1 + "listaddressgroupings"
    d = btc_execute_cmd2(tmp_cmd)
    # print('output:', d)
    d = re.sub('[, [\]\n]', '', d)
    # print('去掉无用字符， \\\\n', d)
    d = d.split('"')
    print(d)
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
        if d[i*4+2] in addresses.keys():
            # print("repeat", addresses[d[i*4+2]])
            addresses[d[i*4+2]][d[i*4]] = d[i*4+1]
        else:
            addresses[d[i*4+2]] = {d[i*4]: d[i*4+1]}
        # print(addresses)
    return addresses


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


# example:
# bitcoin-cli -regtest createrawtransaction
# "[{\"txid\":\"91a4cf439c66776c4e684256d868c7d6c78e356b0b9205b9b9f869a508f4e4ff\",\"vout\":0}]"
# "{\"2NEP5DJ7omMCr7Bvqmg8RBPCBZdTDNYSkuc\":49.9999}"
# 其中TX和ADDRESSES分别是两个列表，每个元素为一个字典。
# TX = [{'txid': --, 'vout':--}, ...]
# ADDRESSES = [{'address': --, 'value': --}, ...]
# 返回执行结果
def btc_createrawtracsaction(TX, ADDRESSES_VALUE):
    print('UTXO:', TX, '\n', 'AV对：', ADDRESSES_VALUE)
    tmp_cmd = fix_cmd + 'createrawtransaction "['

    for txid in TX:
        tmp_cmd = tmp_cmd + '{\\"txid\\":\\"%s\\",\\"vout\\":%s},' % (txid['txid'], txid['vout'])
    tmp_cmd = tmp_cmd[:-1] + ']\" \"{'

    for address_value in ADDRESSES_VALUE:
        tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (address_value['address'], address_value['value'])
    tmp_cmd = tmp_cmd[:-1] + '}"'
    print(tmp_cmd)
    return btc_execute_cmd(tmp_cmd)


# 查找某地址未被花费的UTXO
# 其中confirm_min为被确认次数的最小值
# 返回一个字典字典结构为{txid : {该txid对应的UTXO中的信息}, ...}
# 该txid对应的UTXO中的信息也以字典形式返回，eg:{'vout': '0', ..}
# 信息包括vout, address, label, redeemScript, scriptPubKey, amount, confirmations, spendable, solvabel, desc, safe
# 及以txid为唯一索引建立的字典
def btc_listunspent(confirm_min, confirm_max, address):
    UTXO_PARA_num = 12  # 一个UTXO中的参数个数
    tmp_cmd = fix_cmd + 'listunspent ' + str(confirm_min) + ' ' + str(confirm_max) + ' '
    tmp_cmd += '"[\\"' + address + '\\"]"'
    # print(tmp_cmd)
    UTXO = btc_execute_cmd(tmp_cmd)
    # print("UTXO:", UTXO)
    print("UTXO_len:", len(UTXO))
    UTXO = re.sub('[, :{}[\]\n]', '', UTXO)
    # print(UTXO)
    UTXO = UTXO.replace('""', '"')
    # print(UTXO)
    UTXO = UTXO[1:].split('"')
    UTXO_num = int(len(UTXO) / (UTXO_PARA_num * 2))
    ret = dict()
    for i in range(UTXO_num):
        start_index = i*UTXO_PARA_num*2  # 在UTXO中txid这个字符串所在的位置索引
        ret[UTXO[start_index + 1]] = dict()
        for j in range(int(UTXO_PARA_num - 1)):
            ret[UTXO[start_index + 1]][UTXO[start_index + 2 + j * 2]] = UTXO[start_index + 3 + j * 2]
            # print(i * UTXO_PARA_num + 2 + j * 2, i * UTXO_PARA_num + 3 + j * 2)
    return ret


# 返回某地址的私钥
def btc_dumpprivkey(address):
    tmp_cmd = fix_cmd1 + 'dumpprivkey ' + address
    privatekey = btc_execute_cmd2(tmp_cmd)
    return privatekey[:-1]


# 签名函数，返回签名结果中hex的部分
def btc_sign_withkey(raw_hex, private_key):
    tmp_cmd = fix_cmd1 + 'signrawtransactionwithkey ' + raw_hex + ' [\\"' + private_key + '\\"]'
    tmp_cmd = tmp_cmd.replace("\n", "")
    hex = btc_execute_cmd2(tmp_cmd)
    hex_split = hex.split('"')
    return hex_split[3]


def btc_createrawtracsaction2(oplist,ADDRESSES_VALUE):

    #print('UTXO:', TX, '\n', 'AV对：', ADDRESSES_VALUE)
    tmp_cmd = fix_cmd1 + 'createrawtransaction "['

    for i in oplist:
        tmp_cmd = tmp_cmd + '{\\"txid\\":\\"%s\\",\\"vout\\":%s},' % (oplist[i].txid, oplist[i].vout)
    tmp_cmd = tmp_cmd[:-1] + ']\" \"{'

    for address_value in ADDRESSES_VALUE:
        tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (address_value['address'], address_value['value'])
    tmp_cmd = tmp_cmd[:-1] + '}"'
    print(tmp_cmd)
    return btc_execute_cmd(tmp_cmd)


def btc_sendrawtx(tx):
    tx_hex = serialize.tobuf_tx(tx).hex()
    tmp_cmd = fix_cmd1 + "sendrawtransaction " + tx_hex
    # when setting 0 for maxfeerate, sendtx will fail
    #tmp_cmd = fix_cmd1 + "sendrawtransaction " + tx_hex + " " + str(0)
    return btc_execute_cmd2(tmp_cmd)


def btc_decoderawtransaction(txid):
    tmp_cmd = fix_cmd + 'decoderawtransaction '
    tmp_cmd += '"' + txid + '"'
    return btc_execute_cmd(tmp_cmd)


def btc_decoderawtransaction2(txid):
    tmp_cmd = fix_cmd1 + ' decoderawtransaction '
    tmp_cmd += '"' + txid + '"'
    return btc_execute_cmd2(tmp_cmd)


def btc_getrawtransaction(txid):
    tmp_cmd = fix_cmd + 'getrawtransaction '
    tmp_cmd += '"' + txid + '"'
    return btc_execute_cmd(tmp_cmd)

'''
def btc_getrawtransaction2(txid):
    tmp_cmd = fix_cmd1 + 'getrawtransaction '
    tmp_cmd += '"' + txid + '"'
    return btc_execute_cmd2(tmp_cmd)
'''


# 发送裸交易
def btc_sendrawtransaction(signed_hex):
    tmp_cmd = fix_cmd1 + 'sendrawtransaction ' + "\"" + signed_hex + "\""
    return btc_execute_cmd2(tmp_cmd)

#def btc_signrawtransaction(raw_hex):


# msg为要隐匿的消息，lamda为两个λ，将两个λ分别插入消息前后
# 并在插入后的前后位置生成随机字符串，并检查是否包含λ子串，如有则重新生成
# rdm_str 的长度为len(msg)/4~len(msg)/2之间的随机值
# λ长度为17bit
def create_shadow_msg(msg, lamda):
    MIN_SIZE = int(len(msg) / 4)
    MAX_SIZE = len(msg)
    # 生成λ_start前面的字符串
    start_str = encryption.create_rdmbin_str_exclude(random.randint(MIN_SIZE, MAX_SIZE), lamda[0])
    end_str = encryption.create_rdmbin_str_exclude(random.randint(MIN_SIZE, MAX_SIZE), lamda[1], 'tail')
    shadow_msg = start_str + lamda[0] + msg + lamda[1] + end_str
    test.write_file('btc_log.txt', 'random_str_start:' + start_str)
    test.write_file('btc_log.txt', 'random_str_end:' + end_str)
    test.write_file('btc_log.txt', 'hidden_message_all' + shadow_msg)
    print('msg_shd:', shadow_msg)
    return shadow_msg


# 连接γ_start,info,γ_end,并补全至21位
# 其中gama为一个含有两个元素的列表，包含γ_start,info,γ_end
def create_value(msg, gama):
    print('value_msg:', msg)
    VALUE_LEN = 25
    DEC_NUM = 8
    msg_shadow = gama[0] + msg + gama[1]
    #msg_shadow = msg+gama[1]
    str_len = VALUE_LEN - len(msg_shadow)
    start_str_num = random.randint(2, str_len - 2)
    # print(start_str_num)
    end_str_num = str_len - start_str_num
    #end_str_num = str_len
    # print(end_str_num)
    start_str = encryption.create_rdmbin_str_exclude(start_str_num, gama[0])
    end_str = encryption.create_rdmbin_str_exclude(end_str_num, gama[1], 'tail')
    value_bin = start_str + msg_shadow + end_str
    #value_bin = msg_shadow + end_str
    print('value_bin:', value_bin)
    value_dec = int(value_bin, 2)
    # print(value_dec)
    value = encryption.int2nfloat(str(value_dec), DEC_NUM)#将十进制的value转化为小数点后有8位的小数
    return value


# 提取函数btc_listaddressgroupings返回值中的所有地址
def btc_get_addresses():
    groupings = btc_listaddressgroupings()
    labels = list(groupings.keys())
    addresses = list()
    for label in labels:
        addresses += list(groupings[label].keys())
    return addresses


# 返回address转换为2进制后的后n位
def get_addr_tail(addr, n):
    address_lastn = encryption.hex2bin(encryption.address_to_P2SH(addr))[-n:]
    return address_lastn


# 输入参数为一个字符串，对应客户端中的某个账号信息。
# 例如：比特币和莱特币中对应label，比特币现金中对应account字段
# 需要检验输入是否正确若输入account不存在返回False，并输出详细的报错信息。
# eg："输入为account：XXX，该输入账号不存在
# 现在存在的account有：[a,b,c,,,]"
# 输出一个字典，key字段为一个字符串，为一个有效地址；value字段为一个字符串，为该地址对应的钱数（单位分别为：BTV）

def get_BTC_account_addresses(account):
    all_addresses = btc_listaddressgroupings()
    # print(all_addresses)
    if account not in all_addresses.keys():
        return {}
    return all_addresses[account]


# 选择正确的地址， 计算出value的大小， 进化γ后并返回，其中msg前5位存储到地址中
# 返回值为，新的γ，找到的address，计算好的value
# 若剩余msg不足5位，则末位补0至5位，找到对应的address
def select_address_value(gama, msg, lamda, rest_addresses):
    print('msg:', msg)#这里的msg为每一对AV需要处理的信息
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


# 选择当前钱数最多的地址的txid并使得选择的txid的总钱数大于需要的value值
def btc_select_top_txid(value_sum):
    # 获得钱数最多的地址
    addresses = btc_listaddressgroupings()
    max_btc = 0
    address = 0
    labels = list(addresses.keys())
    for label in labels:
        addrs = list(addresses[label].keys())
        for addr in addrs:
            if float(addresses[label][addr]) > float(max_btc):
                address = addr
                max_btc = addresses[label][addr]

    # 获取该地址的txid，直到满足总的钱数大于所需的钱数
    tmp_value = 0  # 当前的txid的总钱数
    print('address:', address)
    print('max_btc:', max_btc)
    all_txid = btc_listunspent(1, 99999, address)
    print('all_txid:', all_txid)
    keys = list(all_txid.keys())
    TXID = list()  # 返回的txid：vout对
    for txid in keys:
        TXID.append({'txid': txid, 'vout': all_txid[txid]['vout']})
        value = float(all_txid[txid]['amount'])
        tmp_value += value
        # if value < 0.000001:
        #     print("zero_value:", value)
        #     time.sleep(1)
        # print("tmp_value:", value)
        if tmp_value > value_sum:
            break
    return TXID, address, tmp_value


# 选择默认账号中的某一个地址，使其UTXO的余额之和满足大于value_sum
def btc_select_UTXO(value_sum):
    # 找第一个其UTXO余额满足value_sum的地址
    label = ''
    flag = 0
    TXID = list()
    tmp_value = 0
    valid_address = 0

    addresses = get_BTC_account_addresses(label)
    addresses = list(addresses.keys())
    for addr in addresses:
        TXID = list()
        tmp_value = 0
        flag = 0
        all_txid = btc_listunspent(1, 99999, addr)#返回字典{txid:{UTXO描述字典}，txid:{对应UTXO字典}，……}
        keys = list(all_txid.keys())
        for txid in keys:
            TXID.append({'txid': txid, 'vout': all_txid[txid]['vout']})#该地址拥有的金额总数满足条件的所有tx
            if len(TXID) > 75:
                flag = 2
                break
            value = float(all_txid[txid]['amount'])
            tmp_value += value
            print("addr:%s tmp_value:%s" % (addr, tmp_value))
            if tmp_value > value_sum:
                valid_address = addr
                flag = 1
                break
        if flag == 1:
            break
        elif flag == 2:
            continue
    if flag == 0:
        ex = Exception("没有满足UTXO余额的和大于value_sum的地址")
        raise ex
    else:
        return TXID, valid_address, tmp_value


# 选择某地址的txid，直到满足钱数要求
def btc_select_addr_txid(address, value_sum):

    # 获取该地址的txid，直到满足总的钱数大于所需的钱数
    tmp_value = 0  # 当前的txid的总钱数
    all_txid = btc_listunspent(1, 99999, address)
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


# 根据信息生成交易单并返回剩余字符串和交易单ID以及最新的γ，λ，然后签名后广播
# msg_shad为隐藏信息, _from_label为发送者label，_to_label为发送者的label
# gama，lamda是两个list，分别存储 start和end
def btc_create_one_transaction(msg_shad, gama, lamda):
    # print('msg_shad : ', msg_shad)
    # print('gama:', gama)
    # print('lamda:', lamda)
    label = ''  # 传递信息的账号的label
    MIN_INFO_NUM = 3  # 每个value中隐藏信息的最小值
    MAX_INFO_NUM = 7
    ADDRESS_INFO_NUM = 5  # 每个地址中隐藏信息的大小
    MAX_VALUE_NUM = 30  # address, value对的最大数量
    MIN_VALUE_NUM_RDM = 20  # value, address对数量随机时的最小值
    ADDRESSES_VALUE = list()
    msg_block = list()  # 存储每个AV对中value存储的信息bit数量
    sum_num = 0
    block_num = 0  # value, address对的实际使用量
    value_sum = 0  # 总共需要花费的value数量
    msg_shd_all = ''

    # 计算30个address，value对是否足够容纳9该msg
    for i in range(MAX_VALUE_NUM):
        #block_size = random.randint(MIN_INFO_NUM, MAX_INFO_NUM)#每个value中隐藏的比特位数
        block_size = 14
        msg_block.append(block_size)
        sum_num += block_size + ADDRESS_INFO_NUM#一个AV对总共可以隐藏的位数
    if sum_num >= len(msg_shad):
        block_num = 30
    else:
        block_num = random.randint(MIN_VALUE_NUM_RDM, MAX_VALUE_NUM)

    # 开始生成交易单
    msg_tmp = msg_shad
    print('block_num:', block_num)
    all_addresses = get_BTC_account_addresses(label)
    rest_addresses = list(all_addresses.keys())
    # rest_addresses = btc_get_addresses()  # 存储当前剩余可选的addresses
    if check_addr in rest_addresses:
        rest_addresses.remove(check_addr)#将找零地址check_addr从剩余可选的address中移除
    for i in range(block_num):
        # 若剩余字符为空则跳出循环
        # 若剩余字符数量小于下一个AV对存储的数量则将下一个AV对存储的字符数量设置为字符剩余数量
        # 若当前剩余字符数量足够多则下一个AV对的存储数量为随机生成的存储数量
        if msg_shad == '':
            break
        elif len(msg_shad) < msg_block[i] + ADDRESS_INFO_NUM:
            info_num = len(msg_tmp)
        else:
            info_num = msg_block[i] + ADDRESS_INFO_NUM
        msg_tmp = msg_shad[:info_num]
        address_tmp, value_tmp = select_address_value(gama, msg_tmp, lamda, rest_addresses)  # 找合适AV对
        if address_tmp == 0:
            break
        rest_addresses.remove(address_tmp)#移除选定的地址，实现一次一地址
        gama = encryption.create_gama(gama, lamda)#未实现
        ADDRESSES_VALUE.append({'address': address_tmp, 'value': value_tmp})
        msg_shd_all += msg_tmp  # 将该次隐藏的信息累加
        msg_shad = msg_shad[info_num:]#删掉已经处理过的msg,将剩下的待处理消息赋值给msg_shad
        print('rest msg:', msg_shad)
        value_sum += float(value_tmp)
    TXID, addr, real_value = btc_select_UTXO(value_sum)
    if real_value - value_sum > 0.0001:
        check_value = real_value - value_sum - 0.0001
        print("real_value:%s value_sum:%s, check_value", real_value, value_sum, check_value)
        check_value = format(check_value, '.8f')  # 保留八位小数，以防float计算导致小数点位数过多
        ADDRESSES_VALUE.append({'address': check_addr, 'value': check_value})
    start = time.time()
    txid = btc_createrawtracsaction(TXID, ADDRESSES_VALUE)
    end = time.time()
    print("创建交易单时间：",end - start)

    tmp_prikey = btc_dumpprivkey(addr)
    signed_hex = btc_sign_withkey(txid, tmp_prikey)#签名结果中hex部分
    tx = btc_sendrawtransaction(signed_hex).replace('\n', '')
    print("send_txid:", tx)
    decode = btc_decoderawtransaction(signed_hex)
    test.write_file('btc_log.txt', 'hidden_message_segment:' + msg_shd_all)
    print("tx_decode:", decode)
    test.write_file('btc_log.txt', decode)

    new_gama = gama
    rest_msg = msg_shad
    # print('rest_msg:', rest_msg)
    # print('txid:', txid)
    return rest_msg, new_gama, tx, addr


# text为发送信息
# key为加密密钥，共包含五个密钥，分别为AES加密密钥，λ_start,λ_end,γ0_start,γ0_end
# key是一个包含5个元素的列表 key = [AES_key, λ_start,λ_end,γ0_start,γ0_end]
def btc_send_message(text, key):
    AES_key = key[0]
    text_encrypt = encryption.AES_encrypt(text, AES_key).decode()
    print('text_encrtpt', text_encrypt)
    text_bin = encryption.hex2bin(text_encrypt)#密文的二进制格式
    # print("text_encrypt_bin:", text_encrypt)
    lamda = [key[1], key[2]]
    text_shadow = create_shadow_msg(text_bin, lamda)  # 转换为 rdm_str + λ_start + C + λ_end + rdm_str
    tmp_msg = text_shadow
    # print("text_shadow:", text_shadow)
    gama = [key[3], key[4]]
    TXID = list()
    sender_addrs = list()

    # 直到消息传递完成
    # 生成交易单，并返回剩下的信息tmp_msg,新的γ, 交易单的ID
    while tmp_msg != '':
        tmp_msg, gama, signed_hex, sender = btc_create_one_transaction(tmp_msg, gama, lamda)
        TXID.append(signed_hex)
        sender_addrs.append(sender)
    return TXID, sender_addrs


def btc_send_message2(text, key):
    test.write_file('btc_log.txt', 'valid_message:' + text)
    lamda = [key[1], key[2]]
    test.write_file('btc_log.txt', 'lamda_start:' + lamda[0])
    test.write_file('btc_log.txt', 'lamda_end:' + lamda[1])
    text_shadow = create_shadow_msg(text, lamda)  # 转换为 rdm_str + λ_start + C + λ_end + rdm_str
    tmp_msg = text_shadow
    # print("text_shadow:", text_shadow)
    gama = [key[3], key[4]]
    TXID = list()
    sender_addrs = list()

    # 直到消息传递完成
    # 生成交易单，并返回剩下的信息tmp_msg,新的γ, 交易单的ID
    while tmp_msg != '':
        tmp_msg, gama, signed_hex, sender = btc_create_one_transaction(tmp_msg, gama, lamda)
        TXID.append(signed_hex)
        sender_addrs.append(sender)
    return TXID


def btc_receive_message2(key, txid):
    ADDR_LAST = 5  # 采用的addr后的位数
    [AES_key, lamda_start, lamda_end, gama_start, gama_end] = key
    msg_shd = ''
    all_AV = list()
    for i in range(len(txid)):
        # print(signed_hex[i])
        signed_hex = btc_getrawtransaction(txid[i]).replace('\n', '')
        tx = btc_decoderawtransaction(signed_hex)
        AV = get_AV_fromtx(tx)
        all_AV += AV
    print(all_AV)
    for i in range(len(all_AV)):
        if all_AV[i]['address'] == check_addr:
            continue
        lastn = get_addr_tail(all_AV[i]['address'], ADDR_LAST)
        print('lastn:', lastn)
        value_int = encryption.float2int(all_AV[i]['value'])
        print('value_int:', value_int)
        value_str = bin(int(value_int))[2:]
        print('value_str:', value_str)
        value_valid = encryption.find_valid_str(value_str, gama_start, gama_end)
        msg_shd += lastn + value_valid
        [gama_start, gama_end] = encryption.create_gama([gama_start, gama_end], [lamda_start, lamda_end])
    msg_shd = encryption.sub_0tail(msg_shd)
    msg_encrypted = encryption.find_valid_str(msg_shd, lamda_start, lamda_end)
    return msg_encrypted


def btc_receive_message(key, txid):
    ADDR_LAST = 5  # 采用的addr后的位数
    [AES_key, lamda_start, lamda_end, gama_start, gama_end] = key
    msg_shd = ''
    all_AV = list()
    for i in range(len(txid)):
        # print(signed_hex[i])
        signed_hex = btc_getrawtransaction(txid[i]).replace('\n', '')
        tx = btc_decoderawtransaction(signed_hex)#交易的json对象
        AV = get_AV_fromtx(tx)
        all_AV += AV
    print(all_AV)
    for i in range(len(all_AV)):
        if all_AV[i]['address'] == check_addr:
            continue
        lastn = get_addr_tail(all_AV[i]['address'], ADDR_LAST)#msg的前五位
        print('lastn:', lastn)
        value_int = encryption.float2int(all_AV[i]['value'])#先转换成int再转换为bin二进制
        print('value_int:', value_int)
        value_str = bin(int(value_int))[2:]
        print('value_str:', value_str)
        value_valid = encryption.find_valid_str(value_str, gama_start, gama_end)#提取出msg_shad
        #value_valid = encryption.find_valid_str2(value_str,gama_end)
        msg_shd += lastn + value_valid
    print(msg_shd)
    msg_shd = encryption.sub_0tail(msg_shd)#去掉msg_shd末尾的0
    msg_encrypted = encryption.find_valid_str(msg_shd, lamda_start, lamda_end)
    print('msg_shd_decode:', msg_shd)
    print('msg_encrypted:', msg_encrypted)
    msg = encryption.AES_decrypt(encryption.bin2hex(msg_encrypted).encode(), AES_key)
    return msg


# 生成地址，直到所有地址的后m位的种类数达到n类
def btc_generate_n_addr(m, n):
    label = ''
    if n > 2 ** m:
        ex = Exception("n不能超过2^m")
        raise ex
    while 1:
        all_addresses = get_BTC_account_addresses(label)
        all_addresses = list(all_addresses.keys())
        print("all_Addresses:", all_addresses)
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
            new_addr = btc_getnewaddress()
            btc_generatetoaddress(10, new_addr)
            print("新生成的地址为：", new_addr)


# 输入信息：发送地址from_address, 接收地址to_address, 发送金额value
# 输出信息：若交易成功返回交易hash，交易时间；若失败返回报错信息（如xx输入不满足要求）
def ui_transfer_bitcoin(from_address, to_address, value):
    TXID, sum_value = btc_select_addr_txid(from_address, value)
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
    out = btc_createrawtracsaction(TXID, ADDRESSES_VALUE)#返回生成的未签名交易的序列化字符串
    if not out:
        errorinfo = "接受地址错误"
        return errorinfo
    txid = out
    pri_key = btc_dumpprivkey(from_address)
    signed_hex = btc_sign_withkey(txid, pri_key)
    ret = btc_sendrawtransaction(signed_hex)
    ret = ret.replace('\n', '')
    return ret


def btc_importaddress(address, label):
    tmp_cmd = fix_cmd1 + " importaddress " + address + " " + label
    return btc_execute_cmd2(tmp_cmd)


def btc_listunspent2(account):
    '''
    if wallet_id == 1:
        f_cmd = fix_cmd1
    elif wallet_id == 2:
        f_cmd = fix_cmd1
    else:
        f_cmd = fix_cmd3
    '''
    tmp_cmd = fix_cmd1 + " listunspent 0 99999 [\\\"" + account + "\\\"]"
    UTXO_PARA_num = 10  # 一个UTXO中的参数个数
    UTXO = btc_execute_cmd2(tmp_cmd)
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


def btc_getaddressinfo(address):
    tmp = fix_cmd1 + "getaddressinfo " + address
    ret = btc_execute_cmd2(tmp)
    return ret


def is_importaddr(address):
    ret = btc_getaddressinfo(address)
    ret = re.sub('[, [\]\n{}:]', '', ret)
    ret_split = ret.split('"')
    #print(ret_split)
    for i in range(len(ret_split)):
        if ret_split[i] == 'iswatchonly':
            flag = ret_split[i+1]
            if flag == 'true':
                return True
            else:
                return False


def validate_address(address):
    cmd = fix_cmd1+"validateaddress "+address
    ret = btc_execute_cmd2(cmd)
    ret_json = json.loads(ret)
    isvalid = ret_json['isvalid']
    return isvalid


# get all address-balance of the account(lable)
def getall_address_balance(account):
    # listreceivedbyaddress just helps find the address with given label,because it dosen't include the mining reward amount
    cmd = fix_cmd1+"listreceivedbyaddress 0 true true"
    ret = btc_execute_cmd2(cmd)
    list_ret = json.loads(ret)
    ret_dict = dict()
    for i in range(len(list_ret)):
        if list_ret[i]['label'] == account:
            addr = list_ret[i]['address']
            #amount = list_ret[i]['amount']
            # listreivedbyaddress dosen't include the mining reward amount
            _, amount = get_unspent(addr)
            ret_dict[addr] = amount
    return ret_dict


# create a btc new address manually to send transactions
def btc_generatenewaddress():
    sk, pk = crypto.gen_keypair()
    pk_bytes, sk_bytes = crypto.get_byteskeypair(pk, sk)
    address = crypto.gen_address(pk, 'tesenet', 'bitcoin')
    pk_script = crypto.get_btc_pkscript(pk, 'testnet')
    find = DB_select.check_pkscript(pk_script)
    if not find:
        DB_insert.addr_insert(pk_script, pk_bytes, sk_bytes, 'bitcoin')
    else:
        raise Exception("the address already exsits")
    '''
    btc_importaddress(address)
    if not is_importaddr(address):
        raise Exception("importaddress failed!")
    '''
    return address


#  :the list of Outpoint including txid and vout,tmp_value:unspent money
def get_unspent(address):
    tmp_value = 0  # 当前的txid的总钱数
    all_txid = btc_listunspent2(address)
    keys = list(all_txid.keys())
    Outpoint = namedtuple('Outpoint', ['txid', 'vout'])
    oplist = list()
    for txid in keys:
        outpoint = Outpoint(txid, int(all_txid[txid]['vout']))
        oplist.append(outpoint)
        # tmp_value += float(all_txid[txid]['amount'])
        tmp_value += Decimal(all_txid[txid]['amount'])

        if tmp_value == tmp_value.to_integral():
            tmp_value = tmp_value.to_integral()
        else:
            tmp_value = tmp_value.normalize()

        # print("tmp_value:", tmp_value)
    tmp_value = format(float(tmp_value), '.3f')
    return oplist, tmp_value


# [\"cNcgDhTPiF61Qct9LT8YRxb9AeRAo9CoFTNk3sErYmxuAem312rx\"]

def btc_signrawtxwithkey(tx_hex, privkey):
    tmp = fix_cmd1 + "signrawtransactionwithkey " + tx_hex + " [\\\"" + privkey +"\\\"]"
    ret = btc_execute_cmd2(tmp)
    ret = re.sub('[, [\]\n{}:]', '', ret)
    ret_split = ret.split('"')
    for i in range(len(ret_split)):
        if ret_split[i] == 'hex':
            signhex = ret_split[i+2]
    return signhex


# ret_json is a list: [{”address“:xx, "category":xx....},{....},......{...}]
def btc_listtransactions(count, listfrom):
    tmp = fix_cmd1 + "listtransactions \"*\" " + str(count) + " " + str(listfrom) + " true"
    print(tmp)
    ret = btc_execute_cmd2(tmp)
    ret_json = json.loads(ret)
    return ret_json


'''
def btc_getrawtransaction2(txid):
    tmp = fix_cmd1 + "getrawtransaction " + txid + " true"
    ret = btc_execute_cmd2(tmp)
    ret_json = json.loads(ret)
    return ret_json
'''


def btc_gettransaction_detail(txid):
    tmp_cmd = fix_cmd1 + "getrawtransaction " + txid +" true"
    ret_json = json.loads(btc_execute_cmd2(tmp_cmd))
    return ret_json


def btc_getrawtransaction2(txid):
    tmp = fix_cmd1 + "getrawtransaction " + txid
    tx_hex = btc_execute_cmd2(tmp)
    return tx_hex


# return the txids of tx created by sender
def get_sender_txid(addr, block_since):
    #listfrom = 0
    txid_list = list()
    ret_json = btc_listsinceblock(block_since)
    #print(ret_json)
    tx_list = ret_json['transactions']
    for i in range(len(tx_list)):
        if tx_list[i].get('address') == addr and tx_list[i]['category'] == 'send':
            txid_list.append(tx_list[i]['txid'])
    return txid_list


def btc_getblockcount():
    tmp_cmd = fix_cmd1+"getblockcount"
    blocknum_str = btc_execute_cmd2(tmp_cmd)
    return int(blocknum_str)


def btc_listsinceblock(since_block):
    #获得当前区块高度，减6获得since_block,
    # getblockcount,getblock num获得哈希值
    # listsinceblock "hash" 6 true

    tmp_cmd = fix_cmd1 + "getblockhash " + str(since_block)
    block_hash = btc_execute_cmd2(tmp_cmd)  # the rpc return result has an extra null str
    tmp_cmd = fix_cmd1+"listsinceblock " + block_hash.strip() + " 1 true"
    ret = btc_execute_cmd2(tmp_cmd)
    ret_json = json.loads(ret)
    return ret_json


def get_vout_addrlist(txid):
    addr_list = list()
    tx_detail = btc_gettransaction_detail(txid)
    vout_list = tx_detail['vout']
    for i in range(len(vout_list)):
        tmp_addr_list = vout_list[i]['scriptPubKey']['addresses']
        for j in range(len(tmp_addr_list)):
            addr_list.append(tmp_addr_list[j])
    return addr_list


def get_sending_txidlist(blocksince):
    txid_list = list()
    ret_json = btc_listsinceblock(blocksince)
    tx_list = ret_json['transactions']
    for i in range(len(tx_list)):
        if tx_list[i]['category'] == 'send':
            txid = tx_list[i]['txid']
            txid_list.append(txid)
    return txid_list


def mining(address, number):
    tmpcmd = fix_cmd1+"generatetoaddress "+" " + str(number)+" "+address
    txid_list = btc_execute_cmd2(tmpcmd)
    return txid_list


def ui_send_btctx(db_name, fromaddr, toaddr, amount):
    oplist, value = get_unspent(fromaddr)
    if value == 0:
        raise Exception("insufficent balance!")
    tmp_cmd = fix_cmd1 + 'createrawtransaction "['

    for i in range(len(oplist)):
        tmp_cmd = tmp_cmd + '{\\"txid\\":\\"%s\\",\\"vout\\":%s},' % (oplist[i].txid, oplist[i].vout)
    tmp_cmd = tmp_cmd[:-1] + ']\" \"{'
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (toaddr, amount)
    change_amount = Decimal(str(value)) - Decimal(str(amount)) - Decimal('0.001')
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (fromaddr, change_amount)
    tmp_cmd = tmp_cmd[:-1] + '}"'
    raw_hex = btc_execute_cmd2(tmp_cmd)
    sk_b_special = DB_select.get_skb_by_msgreceiveraddr(db_name, fromaddr, 'bitcoin')
    sk_b_self = DB_select.get_skb_by_selfaddr(db_name, fromaddr, 'bitcoin')
    sk_b = sk_b_self or sk_b_special
    if sk_b:
        wif_sk = crypto.get_wifsk(sk_b)
        wif_sk_str = wif_sk.decode("utf-8")
        signed_hex = btc_sign_withkey(raw_hex, wif_sk_str)
        txid = btc_sendrawtransaction(signed_hex)
        return txid
    else:
        raise Exception("no skb,createtx failed!")

# ———————同步部分——————————
# ———————receiver————————
def receiver_sendtx(address, to_address):
    oplist, value = get_unspent(address)
    tmp_cmd = fix_cmd1 + 'createrawtransaction "['

    for i in range(len(oplist)):
        tmp_cmd = tmp_cmd + '{\\"txid\\":\\"%s\\",\\"vout\\":%s},' % (oplist[i].txid, oplist[i].vout)
    tmp_cmd = tmp_cmd[:-1] + ']\" \"{'

    amount = random.randint(1, 5) * pow(10, -3)
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (to_address, amount)
    change_amount = Decimal(str(value)) - Decimal(str(amount)) - Decimal('0.001')
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (address, change_amount)
    tmp_cmd = tmp_cmd[:-1] + '}"'
    raw_hex = btc_execute_cmd2(tmp_cmd)
    sk_b = DB_select.get_skb_by_msgreceiveraddr(address)
    if sk_b:
        wif_sk = crypto.get_wifsk(sk_b)
        wif_sk_str = wif_sk.decode("utf-8")
        signed_hex = btc_sign_withkey(raw_hex, wif_sk_str)
        txid = btc_sendrawtransaction(signed_hex)
        return txid
    else:
        print("no skb,createtx failed!")


# ---------sender----------
# return pk is raw type
def find_special_pk(block_since, num_zero):
    addr_list = list()
    txid_list = list()
    pk_queue = Queue()  # 可能符合该规则的pk不止一个，都存储起来
    ret_json = btc_listsinceblock(block_since)
    tx_list = ret_json['transactions']
    for i in range(len(tx_list)):
        if tx_list[i]['category'] == 'send':
            tmp_addr = tx_list[i].get('address')
            tmp_txid=tx_list[i]['txid']
            print("tx_json:",tx_list[i])
            print("find sp pk tmp_txid:", tmp_txid)
            if not tmp_addr:
                continue
            if tmp_addr in addr_list:
                continue
            tmp_pkhash = crypto.recover_btc_pkhash(tmp_addr)
            tmp_hash = crypto.hashlib.sha256(tmp_pkhash).digest()
            if tmp_hash.hex()[:num_zero] == '0'*num_zero:
                print("find spec_addr:", tmp_addr)
                addr_list.append(tmp_addr)
                #txid_list.append(tx_list[i]['txid'])
                txid=tx_list[i]['txid']
                pk_raw = get_vin_pk(txid)
                return pk_raw
    '''
    for i in range(len(txid_list)):
        pk_raw = get_vin_pk(txid_list[i])
        pk_queue.put(pk_raw)
    '''
    return None


# return type is hexstr
def get_vin_pk(txid):
    tx_detail = btc_gettransaction_detail(txid)
    vin_list = tx_detail['vin']
    vin = vin_list[0]
    script_sig = vin['scriptSig']['asm']
    for i in range(len(script_sig)):
        if script_sig[i] == ']':
            pk_compressed = script_sig[i+2:]
            pk_raw = crypto.recover_pk_fromstr(bytes.fromhex(pk_compressed))
            return pk_raw


def sender_send_btctx(dbname, sender_address, DH_address, amount):
    oplist, value = get_unspent(sender_address)
    if len(oplist) == 0:
        return None
    tmp_cmd = fix_cmd1 + 'createrawtransaction "['

    for i in range(len(oplist)):
        tmp_cmd = tmp_cmd + '{\\"txid\\":\\"%s\\",\\"vout\\":%s},' % (oplist[i].txid, oplist[i].vout)
    tmp_cmd = tmp_cmd[:-1] + ']\" \"{'

    # amount = random.randint(1, 5) * pow(10, -3)
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (DH_address, amount)
    change_amount = Decimal(str(value)) - Decimal(str(amount)) - Decimal('0.001')  # change amount
    tmp_cmd = tmp_cmd + '\\\"%s\\\":%s,' % (sender_address, change_amount)
    tmp_cmd = tmp_cmd[:-1] + '}"'
    # tmp_cmd = fix_cmd1 + "sendtoaddress " + recieve_addr.strip() + " " + str(amount) + " "+ " \" \"  \" \" true true null \"unset\" null 1.1"
    raw_hex = btc_execute_cmd2(tmp_cmd)
    sk_b = DB_select.get_user_skb(dbname, sender_address, 'bitcoin')
    if sk_b:
        wif_sk = crypto.get_wifsk(sk_b)
        wif_sk_str = wif_sk.decode("utf-8")
        signed_hex = btc_sign_withkey(raw_hex, wif_sk_str)
        txid = btc_sendrawtransaction(signed_hex)
        return txid
    else:
        print("no skb,createtx failed!")
        return None


def btc_execute_cmd2(cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.load_system_host_keys()
    client.connect("192.168.56.101", port=22, username="peiqianman", password='123')
    stdin, stdout, stderr = client.exec_command("cd Documents/bitcoin;" + cmd)
    output = stdout.read()
    error = stderr.read()
    if error:
        ex = Exception("命令行运行错误，错误为：\n" + error.decode() + "\n运行的命令行为: " + str(cmd))
        raise ex
    client.close()
    return output.decode()


if __name__ == '__main__':
       '''   
       addr = 'n4EeYL6Hqm4HdZHdHx1YDi5p8ZKjj3pETp'
       ret = get_sender_txid(addr)

       txhex = btc_getrawtransaction2(ret[0])
       txhex = txhex.strip()
       #print(txhex)
       tx = serialize.parse_txbuf(txhex)
       hex_after = serialize.tobuf_tx(tx)
       print(txhex)
       print(hex_after.hex())
       if txhex == hex_after.hex():
           print("equal")
       else:
           print("fail")
       '''
       '''
       txid = "d00307ad874752e9baefe93274db5d5a7fd6165dfbe439fe8f5db1eabc58f952"
       vout_list = get_vout_addrlist(txid)
       print(vout_list)
       '''
       print(getall_address_balance('Alice'))