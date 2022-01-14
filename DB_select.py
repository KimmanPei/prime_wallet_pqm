import sqlite3
import crypto
import DB_insert, DB_select


def to_usdict(tx_record):
    tx_list = list()
    for tx in tx_record:
        tmp_tx = dict()
        tmp_tx['type'] = tx[5]
        tmp_tx['from_address'] = tx[6]
        tmp_tx['txid'] = tx[1]
        tmp_tx['time'] = tx[2] + ' ' + tx[3]
        tmp_tx['unit'] = tx[5]
        tmp_tx['value'] = tx[4]
        tx_list.append(tmp_tx)
    return tx_list


def get_table_detail(db_name, table_name):
    cmd = "select * from %s order by DATE, TIME" % table_name
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(cmd)
    ret = cursor.fetchall()
    conn.commit()
    conn.close()
    return ret


def get_general_table_detail(db_name, table_name):
    cmd = "select * from %s" % table_name
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(cmd)
    ret = cursor.fetchall()
    conn.commit()
    conn.close()
    return ret


def get_user_detail(db_name, table_name, username):
    cmd = "select * from %s where USER_NAME = '%s'" % (table_name, username)
    # print('cmd:', cmd)
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(cmd)
    ret = cursor.fetchall()
    conn.commit()
    conn.close()
    return ret


def get_type_detail(db_name, table_name, cur_type):
    cmd = "select * from %s where TYPE = '%s'order by DATE, TIME" % (table_name, cur_type)
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(cmd)
    ret = cursor.fetchall()
    conn.commit()
    conn.close()
    return ret


def get_btc_targetaddr():
    cmd = "select * from btc_target_addr"
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(cmd)
    ret = cursor.fetchall()
    conn.close()
    return ret


def get_ltc_targetaddr():
    cmd = "select * from ltc_target_addr"
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(cmd)
    ret = cursor.fetchall()
    conn.close()
    return ret


def get_eth_targetaddr():
    cmd = "select * from eth_target_addr"
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(cmd)
    ret = cursor.fetchall()
    conn.close()
    return ret


def get_pkscript_by_targetaddr(hashid_int, coinname):
    #cmd = "select * from target_addr"
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    if coinname == 'bitcoin':
        cursor.execute("select pkscript from btc_target_addr where id=? ", (hashid_int,))
    elif coinname == 'litecoin':
        cursor.execute("select pkscript from ltc_target_addr where id=? ", (hashid_int,))
    ret = cursor.fetchall()
    conn.close()
    return ret[0][0]


def get_skbytes(dbname, pk_script, coin_name):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    if coin_name == 'bitcoin':
        cursor.execute('select sk from DH_btc_addr where pkscript=?', (pk_script,))
    elif coin_name == 'litecoin':
        cursor.execute('select sk from DH_ltc_addr where pkscript=?', (pk_script,))
    ret = cursor.fetchall()
    conn.close()
    return ret[0][0]


def get_pkbytes(dbname, pk_script, coin_name):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    if coin_name == 'bitcoin':
        cursor.execute('select pk from DH_btc_addr where pkscript=?', (pk_script,))
    elif coin_name == 'litecoin':
        cursor.execute('select pk from DH_ltc_addr where pkscript=?', (pk_script,))
    ret = cursor.fetchall()
    conn.close()
    return ret[0][0]


def check_DH_pkscript(dbname, pk_script, coinname):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    if coinname == 'bitcoin':
        cursor.execute('select pk from DH_btc_addr where pkscript=?', [pk_script,])
    elif coinname == 'litecoin':
        cursor.execute('select pk from DH_ltc_addr where pkscript=?', [pk_script,])
    ret = cursor.fetchall()
    conn.close()
    if ret:
        return True
    else:
        return False


def get_skb_byDHaddr(dbname, coinname, DH_addr):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    if coinname == 'bitcoin':
        cursor.execute('select sk from DH_btc_addr where DHaddr=?', [DH_addr, ])
    elif coinname == 'litecoin':
        cursor.execute('select sk from DH_ltc_addr where DHaddr=?', [DH_addr, ])
    ret = cursor.fetchall()
    conn.close()
    if ret:
        return ret[0][0]
    else:
        return False



def receiver_get_DHskb(dbname, coinname, DH_addr):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    if coinname == 'bitcoin':
        cursor.execute('select DH_skb from check_btc_skaddr where address=?', [DH_addr, ])
    elif coinname == 'litecoin':
        cursor.execute('select DH_skb from check_ltc_skaddr where address=?', [DH_addr, ])
    ret = cursor.fetchall()
    conn.close()
    if ret:
        return ret[0][0]
    else:
        return False


def get_all_DHaddr(dbname, coinname):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    if coinname == 'bitcoin':
        cursor.execute('select DHaddr from DH_btc_addr')
    elif coinname == 'litecoin':
        cursor.execute('select DHaddr from DH_ltc_addr')
    elif coinname == 'ether':
        cursor.execute('select DHaddr from DH_eth_addr')
    ret = cursor.fetchall()
    conn.close()
    DHaddr_list=list()
    if ret:
        for i in range(len(ret)):
            DHaddr_list.append(ret[i][0])
    return DHaddr_list


# initial the flag when generating hash collision
def btc_flag_initial(flag):
    cnt = 0
    retlist = get_btc_targetaddr() # get the all result of target_addr,type:list
    retlen = len(retlist)
    for i in range(retlen):
        hashid = retlist[i][0]
        flag[hashid] = 1
        cnt = cnt + 1
    return cnt


def ltc_flag_initial(flag):
    cnt = 0
    retlist = get_ltc_targetaddr()  # get the all result of target_addr,type:list
    retlen = len(retlist)
    for i in range(retlen):
        hashid = retlist[i][0]
        flag[hashid] = 1
        cnt = cnt + 1
    return cnt


def eth_flag_initial(flag):
    cnt = 0
    cmd = "select * from eth_target_addr"
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(cmd)
    retlist = cursor.fetchall()
    retlen = len(retlist)
    for i in range(retlen):
        hashid = retlist[i][0]
        flag[hashid] = 1
        cnt = cnt + 1
    return cnt


def get_toaddr_by_ethtargetaddr(hashid):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("select toaddr from eth_target_addr where id=? ", (hashid,))
    ret = cursor.fetchall()
    conn.close()
    return ret[0][0]


def check_rawmsg(dbname, addr, sequence):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select * from rawmsg where address=? and sequence=?', (addr, sequence))
    ret = cursor.fetchall()
    conn.close()
    if len(ret):
        return True
    else:
        return False


def check_sessionmsg(dbname, sequence):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select * from session_msg where sequence=?', (sequence, ))
    ret = cursor.fetchall()
    conn.close()
    if len(ret):
        return True
    else:
        return False


def get_content_byrawmsg(dbname, sequence):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select content from rawmsg where sequence=?', (sequence, ))
    ret = cursor.fetchall()
    conn.close()
    # ret is a list, list[i] is a tuple
    if len(ret) == 0:
        return False
    return ret[0][0]


def get_session_msg(dbname, sequence):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select content from session_msg where sequence=?', (sequence,))
    ret = cursor.fetchall()
    conn.close()
    # ret is a list, list[i] is a tuple
    if len(ret) == 0:
        return False
    return ret[0][0]


# ----synchronize-----
def check_msg_receiver_addr(sk_b, coinname, db_name):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    if coinname == 'litecoin':
        cursor.execute('select address from msg_receiver_ltcaddr where sk_b=?', [sk_b])
    elif coinname == 'bitcoin':
        cursor.execute('select address from msg_receiver_btcaddr where sk_b=?', [sk_b])
    ret = cursor.fetchall()
    conn.close()
    if ret:
        return True
    else:
        return False


def check_eth_receiver_addr(sk_b, dbname):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select address from msg_receiver_ethaddr where sk_b=?', [sk_b])
    ret = cursor.fetchall()
    conn.close()
    if ret:
        return True
    else:
        return False


def check_msg_sender_addr(sk_b):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('select count(address) from msg_sender_addr where sk_b=?', [sk_b])
    ret = cursor.fetchall()
    conn.close()
    if ret:
        return True
    else:
        return False


def check_selfaddr(sk_b,  coinname):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    if coinname == 'bitcoin':
        cursor.execute('select count(address) from self_btc_addr where sk_b=?', [sk_b])
    elif coinname == 'litecoin':
        cursor.execute('select count(address) from self_ltc_addr where sk_b=?', [sk_b])
    ret = cursor.fetchall()
    conn.close()
    if ret[0][0]:
        return True
    else:
        return False


def getaddr_by_selfaddr(coinname):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    if coinname == 'bitcoin':
        cursor.execute('select address from self_btc_addr ')
    elif coinname == 'litecoin':
        cursor.execute('select address from self_ltc_addr ')
    ret = cursor.fetchall()
    conn.close()
    if len(ret) == 0:
        return False
    else:
        return ret


def get_skb_by_selfaddr(db_name, addr, coinname):
   # addr_encode = addr.encode("utf-8")
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    if coinname == 'bitcoin':
        cursor.execute('select sk_b from self_btc_addr where address=?', (addr,))
    else:
        cursor.execute('select sk_b from self_ltc_addr where address=?', (addr,))
    ret = cursor.fetchall()
    conn.close()
    # ret is a list, list[i] is a tuple
    if len(ret) == 0:
        return False
    return ret[0][0]


def get_skb_by_msgreceiveraddr(db_name, addr, coinname):
    addr_encode = addr.encode("utf-8")
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    if coinname == 'bitcoin':
        cursor.execute('select sk_b from msg_receiver_btcaddr where address=?', (addr_encode,))
    else:
        cursor.execute('select sk_b from msg_receiver_ltcaddr where address=?', (addr_encode,))
    ret = cursor.fetchall()
    conn.close()
    # ret is a list, list[i] is a tuple
    if len(ret) == 0:
        return False
    return ret[0][0]


def get_all_specialaddr(dbname, coinname):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    if coinname == 'bitcoin':
        cursor.execute('select address from msg_receiver_btcaddr ')
    elif coinname == 'litecoin':
        cursor.execute('select address from msg_receiver_ltcaddr')
    elif coinname == 'ether':
        cursor.execute('select address from msg_receiver_ethaddr')
    ret = cursor.fetchall()
    conn.close()
    specialaddr_list=list()
    if ret:
        for i in range(len(ret)):
            if coinname == 'ether':
                addr = ret[i][0]
            else:
                addr = ret[i][0].decode("utf-8")
            specialaddr_list.append(addr)
    return specialaddr_list


def get_eth_specialaddr(dbname):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select address from msg_receiver_ethaddr')
    ret = cursor.fetchall()
    conn.close()
    specialaddr_list = list()
    if ret:
        for i in range(len(ret)):
            addr = ret[i][0]
            specialaddr_list.append(addr)
    return specialaddr_list


def get_all_eth_DHaddr(dbname):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select DHaddr from DH_eth_addr')
    ret = cursor.fetchall()
    conn.close()
    DHaddr_list = list()
    if ret:
        for i in range(len(ret)):
            addr = ret[i][0]
            DHaddr_list.append(addr)
    return DHaddr_list


# 检查发送者数据库中是否已存在这个DHaddr
def sender_get_eth_DHaddr(dbname, DHaddr,skb):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select DHaddr from DH_eth_addr where sk_b=?', (skb,))
    ret = cursor.fetchall()
    conn.close()
    # ret is a list, list[i] is a tuple
    if len(ret) == 0:
        return False
    else:
        return ret[0][0]


def sender_get_ethDHskb(dbname, DHaddr):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select sk_b from DH_eth_addr where DHaddr=?', (DHaddr,))
    ret = cursor.fetchall()
    conn.close()
    # ret is a list, list[i] is a tuple
    if len(ret) == 0:
        return False
    else:
        return ret[0][0]


def sender_checkethDH_by_DHaddr(dbname, DHaddr):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select * from DH_eth_addr where DHaddr=?', (DHaddr,))
    ret = cursor.fetchall()
    conn.close()
    # ret is a list, list[i] is a tuple
    if len(ret) == 0:
        return False
    else:
        return ret[0][0]

def get_skb_by_msgsenderaddr(addr, coinname):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    if coinname == 'bitcoin':
        cursor.execute('select sk_b from msg_sender_btcaddr where address=?', (addr,))
    else:
        cursor.execute('select sk_b from msg_sender_ltcaddr where address=?', (addr,))
    ret = cursor.fetchall()
    conn.close()
    # ret is a list, list[i] is a tuple
    if len(ret) == 0:
        return False
    else:
        return ret[0][0]


def get_user_skb(dbname, address, coinname):
    if coinname == 'bitcoin':
        skb1 = get_skb_by_msgreceiveraddr(dbname, address, 'bitcoin')
        skb2 = get_skb_by_selfaddr(dbname, address, 'bitcoin')
        skb = skb1 or skb2
    elif coinname == 'litecoin':
        skb1 = get_skb_by_msgreceiveraddr(dbname, address, 'litecoin')
        skb2 = get_skb_by_selfaddr(dbname, address, 'litecoin')
        skb = skb1 or skb2
    return skb


def get_user_ethskb(dbname, address):
    skb1=get_eth_general_skb(dbname, address)
    skb2=get_eth_special_skb(dbname, address)
    skb=skb1 or skb2
    return skb


def get_eth_general_skb(dbname, address):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select sk_b from self_eth_addr where address=?', (address,))
    ret = cursor.fetchall()
    conn.close()
    # ret is a list, list[i] is a tuple
    if len(ret) == 0:
        return False
    else:
        return ret[0][0]


def get_eth_special_skb(dbname, address):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select sk_b from msg_receiver_ethaddr where address=?', (address,))
    ret = cursor.fetchall()
    conn.close()
    # ret is a list, list[i] is a tuple
    if len(ret) == 0:
        return False
    else:
        return ret[0][0]


def get_sender_blocksince(username):
    dbname = 'user.db'
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select blocksince from User_Sender where username=?', [username, ])
    ret = cursor.fetchall()
    conn.close()
    if ret:
        return ret[0][0]
    else:
        return False


def get_sessionid_by_sendersessionID(dbname, DHaddr):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select session_id from sender_sessionID where btc_DHaddr=?', [DHaddr, ])
    ret = cursor.fetchall()
    conn.close()
    if ret:
        return ret[0][0]
    else:
        return False


def get_sessionid_by_checkDHaddr(dbname, btc_DHaddr):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select session_id from check_DHaddr where btc_DHaddr=?', [btc_DHaddr, ])
    ret = cursor.fetchall()
    conn.close()
    if ret:
        return ret[0][0]
    else:
        return False



def check_session_DHaddr(dbname, btc_specaddr, ltc_specaddr, eth_specaddr):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select session_id from check_DHaddr where btc_specaddr=? and ltc_specaddr=? and eth_specaddr=?', [btc_specaddr, ltc_specaddr, eth_specaddr])
    ret = cursor.fetchall()
    conn.close()
    if ret:
        return True
    else:
        return False


# 检查同步地址是否已经在数据库中存在了
def check_DHaddr_exist(dbname, DHaddr, coinname):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    if coinname=='bitcoin':
        cursor.execute('select * from check_btc_skaddr where address=?', [DHaddr, ])
    elif coinname=='litecoin':
        cursor.execute('select address from check_ltc_skaddr where DH_skb=?', [DHaddr, ])
    elif coinname=='ether':
        cursor.execute('select address from check_eth_skaddr where DH_skb=?', [DHaddr, ])
    ret = cursor.fetchall()
    conn.close()
    if ret:
        return ret[0][0]
    else:
        return False


def get_allcoin_DHaddr(dbname, btc_specaddr):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select * from check_DHaddr where btc_specaddr=?', [btc_specaddr, ])
    '''
    elif coinname == 'litecoin':
        cursor.execute('select address from check_ltc_skaddr where DH_skb=?', [DHaddr, ])
    elif coinname == 'ether':
        cursor.execute('select address from check_eth_skaddr where DH_skb=?', [DHaddr, ])
    '''
    ret = cursor.fetchall()
    conn.close()
    if ret:
        btc_DHaddr=ret[0][4]
        ltc_DHaddr=ret[0][5]
        eth_DHaddr=ret[0][6]
        return btc_DHaddr,ltc_DHaddr,eth_DHaddr
    else:
        return False


def receiver_get_ethDHskb(dbname, DHaddr):
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute('select DH_skb from check_eth_skaddr where address=?', [DHaddr, ])
    ret = cursor.fetchall()
    conn.close()
    if ret:
        return ret[0][0]
    else:
        return False
'''
def get_rawmsg():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('select address from rawmsg')
    ret = cursor.fetchall()
    print("ret:", ret[0][0])
    conn.close()
    if ret[0]:
        return True
    else:
        return False
'''

if __name__ == '__main__':
    '''
    sk, pk = crypto.gen_keypair()
    pk_bytes, sk_bytes = crypto.get_byteskeypair(pk, sk)
    pk_script = crypto.get_pkscript(pk)
    DB_insert.p2pkh_addr_insert(pk_script, pk_bytes, sk_bytes)
    check_pkscript(pk_script)
    ret = check_pkscript(pk_script)
    print(ret)
    
    hashid_int = 8
    ret = get_pkscript_by_targetaddr(hashid_int)
    print(ret.hex())
    '''

    #print(get_eth_specialaddr('Bob.db'))
    print(get_all_specialaddr('Bob.db','bitcoin'))
    print(get_all_DHaddr('Alice.db', 'bitcoin'))
    #print(receiver_get_ethDHskb("Bob.db", "0x9B66661db7B65792f4cFb0C7114C001Ba974e9A6").hex())
    #print(sender_get_ethDHskb('Alice.db', "0xF735082655773Cf1ddb99bE032BB8dC93D589b31").hex())