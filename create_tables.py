# -*- coding:utf-8 -*-
import sqlite3


def create_USER_table():
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cmd = '''
    CREATE TABLE "NUM_ADDR"(
    USER_NAME varchar(20) NOT NULL,
    BTC_num int NOT NULL,
    BCH_num int NOT NULL,
    LTC_num int NOT NULL,
    ETH_num int NOT NULL,
    PRIMARY KEY(USER_NAME)
    );'''
    cursor.execute(cmd)
    # values = cursor.fetchall()
    # print(values)
    conn.commit()
    conn.close()


def create_tx_table():
    conn = sqlite3.connect('transaction.db')
    cursor = conn.cursor()
    cmd = '''
    CREATE TABLE "HISTORY"(
    USER_NAME varchar(20) NOT NULL,
    TXID VARCHAR(80) NOT NULL, 
    DATE DATE NOT NULL,
    TIME TIME NOT NULL,
    VALUE NUMERIC(10,24) NOT NULL,
    TYPE CHAR(3),
    FROM_ADDRESS VARCHAR(64),
    TO_ADDRESS VARCHAR(64),
    PRIMARY KEY(USER_NAME,TXID,TO_ADDRESS)
    );'''
    cursor.execute(cmd)
    # values = cursor.fetchall()
    # print(values)
    conn.commit()
    conn.close()


# the database is related to sending secret msg, each user has a database to store realting data
def create_usersendmsg_table(username):
    db_name = username+".db"
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    DH_btc_cmd = '''
    CREATE TABLE DH_btc_addr (
    pkscript BLOB PRIMARY KEY
                  NOT NULL,
    pk       BLOB NOT NULL,
    sk       BLOB NOT NULL,
    DHaddr  TEXT NOT NULL
);'''
    DH_ltc_cmd = '''
    CREATE TABLE DH_ltc_addr (
    pkscript BLOB NOT NULL,
    pk       BLOB NOT NULL,
    sk       BLOB NOT NULL,
    DHaddr  TEXT NOT NULL
);'''
    DH_eth_cmd = '''
    CREATE TABLE msg_receiver_ethaddr (
    sk_b    BLOB NOT NULL,
    pk_b    BLOB NOT NULL,
    DHaddr TEXT NOT NULL
);

    '''
    # msg_reciver get a special address as sending addr to create a tx
    receiver_btcaddr_cmd = '''
    CREATE TABLE msg_receiver_btcaddr (
    sk_b    BLOB NOT NULL
                 PRIMARY KEY,
    pk_b    BLOB NOT NULL,
    address TEXT NOT NULL
);'''
    receiver_ltcaddr_cmd = '''
        CREATE TABLE msg_receiver_ltcaddr (
        sk_b    BLOB NOT NULL
                     PRIMARY KEY,
        pk_b    BLOB NOT NULL,
        address TEXT NOT NULL
    );'''
    receiver_ethaddr_cmd = '''
    CREATE TABLE msg_receiver_ethaddr (
    sk_b    BLOB NOT NULL,
    pk_b    BLOB NOT NULL,
    address TEXT NOT NULL
);
'''

    # 消息发送者生成一个发送地址，创建交易，交易接收地址为DH_addr
    sender_btcaddr_cmd = '''
    CREATE TABLE msg_sender_btcaddr (
    sk_b    BLOB NOT NULL,
    pk_b    BLOB NOT NULL,
    address TEXT NOT NULL
);
'''
    sender_ltc_cmd = '''
    CREATE TABLE msg_sender_ltcaddr (
    sk_b    BLOB NOT NULL,
    pk_b    BLOB NOT NULL,
    address TEXT NOT NULL
);'''
    # self_addr 存储的是消息接收方和发送方所创建交易中的接收地址，为了避免资金流失，生成属于自己的地址作为接收地址进行交易
    self_btcaddr_cmd = '''
    CREATE TABLE self_btc_addr (
    sk_b    BLOB NOT NULL,
    pk_b    BLOB NOT NULL,
    address TEXT NOT NULL
);
'''
    self_ltcaddr_cmd = '''
    CREATE TABLE self_ltc_addr (
    sk_b    BLOB NOT NULL,
    pk_b    BLOB NOT NULL,
    address TEXT NOT NULL
);
'''
    self_ethaddr_cmd = '''
    CREATE TABLE self_eth_addr (
    sk_b    BLOB NOT NULL
                 PRIMARY KEY,
    pk_b    BLOB NOT NULL,
    address TEXT NOT NULL
);
'''
    # 消息发送方创建session的时候需要知道session id， 对于同一组DHaddr，session id依次递增
    sender_sessionid_cmd = '''
    CREATE TABLE sender_sessionID (
    btc_DHaddr TEXT    NOT NULL
                       PRIMARY KEY,
    session_id INTEGER NOT NULL
);
'''
    # 接收方在计算DH地址时也要计算私钥保存下来，便于之后提取隐蔽信息
    check_btc_DHskbaddr=''''
    CREATE TABLE check_btc_skaddr (
    address TEXT NOT NULL,
    DH_skb  BLOB NOT NULL
);
'''
    check_ltc_DHskbaddr=''''
    CREATE TABLE check_ltc_skaddr (
    address TEXT NOT NULL,
    DH_skb  BLOB NOT NULL
);
'''
    check_eth_DHskbaddr=''''
    CREATE TABLE check_eth_skaddr (
    address TEXT NOT NULL,
    DH_skb  BLOB NOT NULL
);
'''
    check_DHaddr_cmd = '''
    CREATE TABLE check_DHaddr (
    session_id   INTEGER NOT NULL,
    btc_specaddr TEXT    NOT NULL,
    ltc_specaddr TEXT    NOT NULL,
    eth_specaddr TEXT    NOT NULL,
    btc_DHaddr   TEXT    NOT NULL,
    ltc_DHaddr   TEXT    NOT NULL,
    eth_DHaddr   TEXT    NOT NULL
);
'''
    raw_msg_cmd = '''
    CREATE TABLE rawmsg (
    address  STRING  NOT NULL,
    sequence INTEGER NOT NULL,
    content  BLOB    NOT NULL
);'''
    session_msg_cmd = '''
    CREATE TABLE session_msg (
    sequence BLOB NOT NULL,
    content  BLOB NOT NULL
);'''
    cursor.execute(DH_btc_cmd)
    cursor.execute(DH_ltc_cmd)
    cursor.execute(DH_eth_cmd)
    cursor.execute(receiver_btcaddr_cmd)
    cursor.execute(receiver_ltcaddr_cmd)
    cursor.execute(receiver_ethaddr_cmd)
    cursor.execute(check_btc_DHskbaddr)
    cursor.execute(check_ltc_DHskbaddr)
    cursor.execute(check_eth_DHskbaddr)
    cursor.execute(self_btcaddr_cmd)
    cursor.execute(self_ltcaddr_cmd)
    cursor.execute(self_ethaddr_cmd)
    cursor.execute(raw_msg_cmd)
    cursor.execute(session_msg_cmd)
    cursor.execute(sender_sessionid_cmd)
    cursor.execute(check_DHaddr_cmd)


def show_table(db_name):
    cmd = "select name from sqlite_master where type='table' order by name"
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(cmd)
    ret = cursor.fetchall()
    conn.commit()
    conn.close()
    return ret


if __name__ == '__main__':
    # create_tx_table()
    username = 'pqm'
    create_usersendmsg_table(username)
    '''
    create_USER_table()
    db_name = 'user.db'
    tables = show_table(db_name)
    print(tables)
    pass
    '''