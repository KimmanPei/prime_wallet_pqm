import sqlite3
import DB_select
import time
import litecoin_client
import bitcoin_client

import crypto


def insert_ethaccount(db_name, username, address, balance):
    str_balance = '%d' % balance
    cmd = 'insert into "ETH_ACCOUNT"(username,address,balance) values(\'' + username + '\',\'' +address + '\',\'' + str_balance + '\')'
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(cmd)
    conn.commit()
    conn.close()


# USER_NAME VARCHAR(20) NOT NULL,
# TXID VARCHAR(80) NOT NULL,
# DATE DATE NOT NULL,
# TIME TIME NOT NULL,
# VALUE NUMERIC(10,24) NOT NULL,
# TYPE CHAR(3),
# FROM_ADDRESS VARCHAR(64),
# TO_ADDRESS VARCHAR(64)
def insert_history(db_name , user_name, txid, date, time, value, TYPE, from_addr, to_addr):
    cmd = 'insert into "HISTORY" values(\'' + user_name + '\',\'' + txid + '\',\'' + date + '\',\'' + time + '\',\'' + value + '\',\'' + TYPE + '\',\'' + from_addr + '\',\'' + to_addr + '\')'
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(cmd)
    conn.commit()
    conn.close()


def insert_num_addr(db_name, user_name, btc_num, bch_num, ltc_num, eth_num):
    cmd = 'insert into "NUM_ADDR" values(\'' + user_name + '\',\'' + btc_num + '\',\'' + bch_num + '\',\'' + ltc_num + '\',\'' + eth_num + '\')'
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(cmd)
    conn.commit()
    conn.close()


# 使某用户的某种币的地址数量+1
def update_num_addr(db_name, user_name, Type):
    table_name = 'NUM_ADDR'
    Type_list = [0, 'BTC', 'BCH', 'LTC', 'ETH']
    idx = Type_list.index(Type)
    ret = DB_select.get_user_detail(db_name, table_name, user_name)
    # print('ret:', ret)
    new_addr_num = int(ret[0][idx]) + 1
    cmd = "update %s set %s_num = %s where USER_NAME = '%s'" % (table_name, Type, new_addr_num, user_name)
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(cmd)
    conn.commit()
    conn.close()
    pass


def update_Sender_blocksince(username, blocksince_new):
    db_name = "user.db"
    cmd = "update User_Sender set %s = %s where username = '%s'" % ('blocksince', blocksince_new, username)
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(cmd)
    conn.commit()
    conn.close()


def insert_sendersessionID(dbname, DHaddr):
    session_id = 0
    cmd = 'insert into "sender_sessionID" values(\'' + DHaddr + '\',\'' + str(session_id) + '\')'
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute(cmd)
    conn.commit()
    conn.close()


def insert_checkDHaddr(dbname, btc_addr, ltc_addr, eth_addr, btcDHaddr, ltcDHaddr,ethDHaddr):
    session_id = 0
    cmd = 'insert into "check_DHaddr" values(\'' + str(session_id) + '\', \'' + btc_addr + '\',\'' + ltc_addr + '\', \'' + eth_addr + '\',\'' + btcDHaddr + '\', \'' + ltcDHaddr + '\', \'' + ethDHaddr + '\')'
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute(cmd)
    conn.commit()
    conn.close()



def update_sendersessionID(dbname, DHaddr, new_sessionid):
    #session_id = DB_select.get_sessionid_by_sendersessionID(dbname,DHaddr)
    table_name = 'sender_sessionID'
    cmd = "update %s set '%s' = %s where btc_DHaddr = '%s'" % (table_name, 'session_id', new_sessionid, DHaddr)
    #cmd = "update"+ table_name+"set"+
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute(cmd)
    conn.commit()
    conn.close()


# 接收方更新session Id,发送消息只需要输入btc_DHaddr
def update_checkDHaddr(dbname, DHaddr, new_sessionid):
    # session_id = DB_select.get_sessionid_by_sendersessionID(dbname,DHaddr)
    table_name = 'check_DHaddr'
    cmd = "update %s set '%s' = %s where btc_DHaddr = '%s'" % (table_name, 'session_id', new_sessionid, DHaddr)
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute(cmd)
    conn.commit()
    conn.close()


def delete_history(db_name):
    cmd = "delete from 'HISTORY' where TXID like '%不足%'"
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(cmd)
    conn.commit()
    conn.close()


def test_insert():
    db_name = "transaction.db"
    user_name = 'test'
    txid = "4c0fe9158364ce3860390eb17665c92ecc1e84e899708a6e6ac964b69a660202"
    date_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    [Date, Time] = date_time.split()
    value = "10"
    TYPE = "BTC"
    from_addr = "2MvgxRLqAq7hVHWChc2DjJ5hdKmRnSMEkYY"
    to_addr = "2NB5v8XAjNsyGDihk3XEGKDEufcPXtTDPRp"
    insert_history(db_name, user_name, txid, Date, Time, value, TYPE, from_addr, to_addr)


def test_show_history():
    DB_name = 'transaction.db'
    Table_name = 'HISTORY'
    # delete_history(DB_name)
    tx_record = DB_select.get_table_detail(DB_name, Table_name)
    tx_list = list()
    if len(tx_record) > 3:
        tx_record = tx_record[-3:]
    for tx in tx_record:
        tmp_tx = dict()
        tmp_tx['type'] = tx[5]
        tmp_tx['from_address'] = tx[6]
        tmp_tx['to_address'] = tx[7]
        tmp_tx['time'] = tx[2] + ' ' + tx[3]
        tmp_tx['unit'] = tx[5]
        tmp_tx['value'] = tx[4]
        tx_list.append(tmp_tx)
    print(tx_list)


def user_insert():
    db_name = 'user.db'
    user_list = ['test', 'mars', 'test1', 'test4', 'ldw']
    for username in user_list:
        num_addr_btc = len(bitcoin_client.get_BTC_account_addresses(username))
        num_addr_bch = len(bitcoincash_client.get_BCH_account_addresses(username))
        num_addr_ltc = len(litecoin_client.get_LTC_account_address(username))
        num_addr_eth = 3
        insert_num_addr(db_name, username, str(num_addr_btc), str(num_addr_bch), str(num_addr_ltc), str(num_addr_eth))


def test_show_num_addr():
    db_name = 'user.db'
    table_name = 'NUM_ADDR'
    username = 'ldw'
    num_addr = DB_select.get_user_detail(db_name, table_name, username)
    (num_add_btc, num_add_bch, num_add_ltc, num_add_eth) = num_addr[0][1:]
    print(num_add_btc, num_add_bch, num_add_ltc, num_add_eth)


def test_user_db():
    db_name = 'user.db'
    table_name = 'NUM_ADDR'
    # insert_num_addr(db_name, 'test100', '0', '0', '0', '0')
    update_num_addr(db_name, 'test100', 'BTC')
    ret = DB_select.get_general_table_detail(db_name, table_name)
    print(ret)


# id (integer): 16bits hash collision
# pkscript (blob): pk_script(bytes type)
# pk (blob): the bytes type of raw pk
# sk (blob): the bytes type of raw sk
def btc_target_addr_insert(hashid_int, pk_script, pk_bytes, sk_bytes):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('insert into btc_target_addr values(?, ?, ?, ?)',
    (hashid_int, pk_script, pk_bytes, sk_bytes))
    conn.commit()  #必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()      #关闭游标
    conn.close()


def ltc_target_addr_insert(hashid_int, pk_script, pk_bytes, sk_bytes):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('insert into ltc_target_addr values(?, ?, ?, ?)',
    (hashid_int, pk_script, pk_bytes, sk_bytes))
    conn.commit()  #必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()      #关闭游标
    conn.close()


# id(integer): 16bits hash collision
# toaddr(blob): receiver address(bytes type)
# pk (blob): the bytes type of raw pk
# sk (blob): the bytes type of raw sk
def eth_target_addr_insert(hashid_int, toaddr, pk_bytes, sk_bytes):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('insert into eth_target_addr values(?, ?, ?, ?)',
              (hashid_int, toaddr, pk_bytes, sk_bytes))
    conn.commit()  # 必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()  # 关闭游标
    conn.close()


# btc_addr/ltc_addr stores the sending addresses which really send secret msg.
# the function is called when generating a new address
# pk_byte and sk_byte are both the bytes type of pk, sk
# coin_name refers the type of blockchain
def DH_addr_insert(dbname, pk_script, pk_byte, sk_byte, DHaddr, coin_name):
    conn = sqlite3.connect(dbname)
    c = conn.cursor()
    if coin_name == 'bitcoin':
        c.execute('insert into DH_btc_addr values(?, ?, ?, ?)',
              (pk_script, pk_byte, sk_byte, DHaddr))
    elif coin_name == 'litecoin':
        c.execute('insert into DH_ltc_addr values(?, ?, ?, ?)',
                  (pk_script, pk_byte, sk_byte, DHaddr))
    conn.commit()  # 必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()  # 关闭游标
    conn.close()


def eth_DHaddr_insert(dbname, sk_byte, pk_byte, DHaddr):
    conn = sqlite3.connect(dbname)
    c = conn.cursor()
    c.execute('insert into DH_eth_addr values(?, ?, ?)',(sk_byte, pk_byte, DHaddr))
    conn.commit()  # 必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()  # 关闭游标
    conn.close()


# address: string
# sequence: integer
# content: blob
def rawmsg_insert(dbname, address, sequence, content):
    conn = sqlite3.connect(dbname)
    c = conn.cursor()
    c.execute('insert into rawmsg values(?, ?, ?)',
              (address, sequence, content))
    conn.commit()  # 必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()  # 关闭游标
    conn.close()


# save the real msg of a session
# address:string
# sequence: integer
# content:blob
# size: integer,size of content
def session_msg_insert(dbname, sequence, content):
    conn = sqlite3.connect(dbname)
    c = conn.cursor()
    c.execute('insert into session_msg values(?, ?)',
              (sequence, content))
    conn.commit()  # 必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()  # 关闭游标
    conn.close()


# -------同步-------
def msg_receiver_insert(sk_b, pk_b, address, coinname, db_name):
    #print("yes")
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    if coinname == 'bitcoin':
        c.execute('insert into msg_receiver_btcaddr values(?, ?, ?)',
                  (sk_b, pk_b, address))
    else:
        c.execute('insert into msg_receiver_ltcaddr values(?, ?, ?)',
                  (sk_b, pk_b, address))
    conn.commit()  # 必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()  # 关闭游标
    conn.close()


def receiver_eth_insert(sk_b, pk_b, address, dbname):
    conn = sqlite3.connect(dbname)
    c = conn.cursor()
    c.execute('insert into msg_receiver_ethaddr values(?, ?, ?)',
              (sk_b, pk_b, address))
    conn.commit()  # 必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()  # 关闭游标
    conn.close()



def msg_sender_insert(sk_b, pk_b, address, coinname):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    if coinname == 'bitcoin':
        c.execute('insert into msg_sender_btcaddr values(?, ?, ?)',
                  (sk_b, pk_b, address))
    else:
        c.execute('insert into msg_sender_ltcaddr values(?, ?, ?)',
                  (sk_b, pk_b, address))
    conn.commit()  # 必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()  # 关闭游标
    conn.close()


def self_addr_insert(sk_b, pk_b, address, coinname, db_name):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    if coinname == 'bitcoin':
        c.execute('insert into self_btc_addr values(?, ?, ?)',
                  (sk_b, pk_b, address))
    else:
        c.execute('insert into self_ltc_addr values(?, ?, ?)',
                  (sk_b, pk_b, address))
    conn.commit()  # 必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()  # 关闭游标
    conn.close()


def self_ethaddr_insert(sk_b, pk_b, address, dbname):
    conn = sqlite3.connect(dbname)
    c = conn.cursor()
    c.execute('insert into self_eth_addr values(?, ?, ?)', (sk_b, pk_b, address))
    conn.commit()  # 必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()  # 关闭游标
    conn.close()


# 接收者计算DHaddr时要保存私钥便于后面的签名验签提取隐蔽信息
def DHskb_insert(sk_b, address, dbname, coinname):
    conn = sqlite3.connect(dbname)
    c = conn.cursor()
    if coinname=='bitcoin':
        c.execute('insert into check_btc_skaddr values(?, ?)', (address, sk_b))
    elif coinname=='litecoin':
        c.execute('insert into check_ltc_skaddr values(?, ?)', (address, sk_b))
    elif coinname=='ether':
        c.execute('insert into check_eth_skaddr values(?, ?)', (address,sk_b))
    conn.commit()  # 必须调用提交事务,否则不会对数据库所做的修改生效
    c.close()  # 关闭游标
    conn.close()


if __name__ == '__main__':
    # test_show_num_addr()
    db_name = 'Bob.db'
    # delete_history(db_name)
    #ret = DB_select.get_general_table_detail(db_name, 'HISTORY')
   # for itr in ret:
        #print(itr)

    addr="abcd"
    #insert_sendersessionID('Alice.db',addr)
    #ret = DB_select.get_sessionid_by_sendersessionID('Alice.db',addr)
    #print(ret)
    #update_sendersessionID('Alice.db', addr)
    insert_checkDHaddr('Bob.db',"btcaddr","ltcaddr","ethaddr","btcDHaddr","ltcDHaddr","ethDHaddr")
