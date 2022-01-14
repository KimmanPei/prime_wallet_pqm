import DB_insert
import crypto
import time
import bitcoin_client
import ether_client
import litecoin_client
import DB_select


# -------receiver-------
# message receiver generate a special address
def get_btc_receiver_addr(num_zero, nettype, label, db_name):
    receiver_addr = crypto.gen_special_addr(num_zero, nettype, 'bitcoin', db_name)
    bitcoin_client.btc_importaddress(receiver_addr, label)
    return receiver_addr


def get_ltc_receiver_addr(num_zero, nettype, label, db_name):
    receiver_addr = crypto.gen_special_addr(num_zero, nettype, 'litecoin', db_name)
    litecoin_client.ltc_importaddress(receiver_addr, label)
    return receiver_addr


def get_eth_receiver_addr(num_zero, username):
    receiver_addr = crypto.gen_special_ethaddr(num_zero, username)
    return receiver_addr


# use the special addr to send a tx
# firstly generate a new address as recieve address of the tx
def receiver_send_Tx(special_addr, coinname):
       addr_tuple_list = DB_select.getaddr_by_selfaddr(coinname)
       if addr_tuple_list:
           i = crypto.random.randint(0, len(addr_tuple_list)-1)
           to_addr = addr_tuple_list[i][0]
       else:
           raise Exception("can't get selfaddr from database!")
       if coinname == 'bitcoin':
           txid = bitcoin_client.receiver_sendtx(special_addr, to_addr)
       elif coinname == 'litecoin':
           txid = litecoin_client.receiver_sendtx(special_addr, to_addr)
       return txid


# 消息接收方计算DHaddr
def btc_check_DHaddr(dbname, receiver_addr, nettype):
    blocksince = bitcoin_client.btc_getblockcount()-6
    skbyte_receiver = DB_select.get_user_skb(dbname, receiver_addr, 'bitcoin')
    print("skb_rec:", skbyte_receiver.hex())
    btc_txid_list = bitcoin_client.get_sending_txidlist(blocksince)
    print("btctxlist:", btc_txid_list)
    for i in range(len(btc_txid_list)):
        pk_sender = bitcoin_client.get_vin_pk(btc_txid_list[i])
        compute_DHaddr, compute_DHskb = crypto.computing_DHaddr(pk_sender, skbyte_receiver, nettype, 'bitcoin')
        addr_list = bitcoin_client.get_vout_addrlist(btc_txid_list[i])
        if compute_DHaddr in addr_list:
            if not DB_select.check_DHaddr_exist(dbname, compute_DHaddr, 'bitcoin'):
                DB_insert.DHskb_insert(compute_DHskb, compute_DHaddr, dbname, 'bitcoin')
            return compute_DHaddr
    return None


def ltc_check_DHaddr(dbname, receiver_addr, nettype):
    blocksince = litecoin_client.ltc_getblockcount() - 6
    skbyte_receiver = DB_select.get_user_skb(dbname, receiver_addr, 'litecoin')
    ltc_txid_list = litecoin_client.get_sending_txidlist(blocksince)
    for i in range(len(ltc_txid_list)):
        pk_sender = litecoin_client.get_vin_pk(ltc_txid_list[i])
        if not pk_sender:
            continue
        compute_DHaddr, compute_DHskb = crypto.computing_DHaddr(pk_sender, skbyte_receiver, nettype, 'litecoin')
        addr_list = litecoin_client.get_vout_addrlist(ltc_txid_list[i])
        if compute_DHaddr in addr_list:
            # 将私钥加入到数据库中
            if not DB_select.check_DHaddr_exist(dbname, compute_DHskb, 'litecoin'):
                DB_insert.DHskb_insert(compute_DHskb, compute_DHaddr, dbname, 'litecoin')
            return compute_DHaddr
    return None


def eth_check_DHaddr(dbname, receiver_addr):
    blocksince = 0
    receiver_skb=DB_select.get_eth_special_skb(dbname, receiver_addr)
    txid_list = ether_client.get_all_txid(blocksince)
    if not txid_list:
        return False
    for txid in txid_list:
        print("eth_txid:",txid)
        sender_pkb=ether_client.recover_pk_fromsig(txid)
        sender_pk=crypto.recover_pk_fromstr(sender_pkb)
        compute_DHaddr, compute_DHskb = crypto.computing_eth_DHaddr(sender_pk, receiver_skb)
        tx_detail = ether_client.eth_get_txdetail(txid)
        tx_toaddr = tx_detail['to']
        if compute_DHaddr==tx_toaddr:
            if not DB_select.check_DHaddr_exist(dbname, compute_DHskb, 'ether'):
                DB_insert.DHskb_insert(compute_DHskb, compute_DHaddr, dbname, 'ether')
            return compute_DHaddr
    return None


# -------sender---------
# message sender query and find the special addr
# bitcoin_client.find_special_address(block_since, num_zero)


# message sender generate a pk_A
def get_sender_addr(nettype, coinname):
    sender_addr = crypto.gen_sender_addr(nettype, coinname)
    if coinname == 'bitcoin':
        bitcoin_client.btc_importaddress(sender_addr)
    elif coinname == 'litecoin':
        litecoin_client.ltc_importaddress(sender_addr)
    return sender_addr


# message sender send a tx including 2 receiver
def sender_justsend_tx(dbname, sender_addr, pk_receiver, coinname, nettype, value):
    sk_bytes_sender = DB_select.get_user_skb(dbname, sender_addr, coinname)
    if coinname == 'bitcoin':
        DH_addr = crypto.DH_btc_sendaddress(dbname, sk_bytes_sender, pk_receiver, nettype)
        txid = bitcoin_client.sender_send_btctx(dbname, sender_addr, DH_addr, value)
    elif coinname == 'litecoin':
        DH_addr = crypto.DH_ltc_sendaddress(dbname, sk_bytes_sender, pk_receiver, nettype)
        txid = litecoin_client.sender_send_ltctx(dbname, sender_addr, DH_addr, value)
    print("DH_addr:", DH_addr)
    return txid, DH_addr


def btc_sender_sendtx(dbname, sender_addr, nettype, num_zero, value):
    blocknow = bitcoin_client.btc_getblockcount()
    blocksince = blocknow - 6
    if blocksince<0:
        blocksince=0
    #blocksince = 0
    pkB_raw = bitcoin_client.find_special_pk(blocksince, num_zero)
    if not pkB_raw:
        print("find pkB failed!")
        return False,False
    sender_txid, DH_addr = sender_justsend_tx(dbname, sender_addr, pkB_raw, 'bitcoin', nettype, value)
    return sender_txid, DH_addr


def ltc_sender_sendtx(dbname, sender_addr, nettype, num_zero, value):
    blocknow = litecoin_client.ltc_getblockcount()
    blocksince = blocknow - 6
    if blocksince<0:
        blocksince=0
    pkB_queue = litecoin_client.find_special_pk(blocksince, num_zero)
    if pkB_queue.empty():
        raise Exception("find pkB failed!")
    pk_B = pkB_queue.get()
    sender_txid, DH_addr = sender_justsend_tx(dbname, sender_addr, pk_B, 'litecoin', nettype,value)
    return sender_txid, DH_addr


# value is bytes type, unit is wei
def eth_sender_sendtx(username, sender_addr, num_zero, value):
    blocksince = 0
    dbname=username+'.db'
    pklist = list()
    pklist = ether_client.find_special_pk(num_zero, blocksince)
    if pklist:
        pk_byte = pklist[0]
    else:
        raise Exception("can't find pk_B")
    pk_B = crypto.recover_pk_fromstr(pk_byte)
    skb_A= DB_select.get_user_ethskb(dbname, sender_addr)
    # DHaddr_raw=toaddr_raw
    toaddr_raw, shared_skhex=crypto.DH_eth_rawsendaddress(dbname,skb_A,pk_B)
    ether_client.eth_importaddress(shared_skhex,username)
    DH_addr=ether_client.to_checksum_address(toaddr_raw)
    gas_limit = int.to_bytes(21000, 2, "big")
    gas_price = int.to_bytes(105000000000, 5, "big")
    value_bytes=value.encode("utf-8")
    txid=ether_client.eth_sendtransaction(username, sender_addr, gas_price, gas_limit, toaddr_raw, value_bytes)
    return txid,DH_addr


if __name__ == '__main__':
    # receiver 生成具有规则的receiver_addr,再生成一个自己的地址作为接收地址，用receiver_addr发起一笔交易
    # sender 先找出具有规则的receiver_addr,生成一个sender_addr，发起一笔交易，其中一个接收地址就是DH_addr
    # receiver 遍历所有交易中的接收地址，逐一进行DH计算出一个DH_addr看是否和交易中的接收地址相同，若相同则是最终的DH_addr
    '''
    numzero = 2
    ltc_receiver_addr = get_ltc_receiver_addr(numzero, 'regtest')
    print("ltc_recie_addr:", ltc_receiver_addr)
    '''
    '''
        btc_sender_addr = get_sender_addr('regtest', 'bitcoin')
        print("btc_sender_addr:", btc_sender_addr)
        '''
    '''
    ltc_sender_addr = get_sender_addr('regtest', 'litecoin')
    print("ltc_sender_addr:", ltc_sender_addr)
    '''
    '''
    numzero = 2
    btc_block_since = bitcoin_client.btc_getblockcount() - 6
    ltc_block_since = litecoin_client.ltc_getblockcount() - 6
    ltc_sender_sendtx(ltc_block_since, ltc_sender_addr, 'regtest', numzero)
    '''
    '''
    numzero = 2
    ltc_block_since = litecoin_client.ltc_getblockcount() - 6
    ltc_sender_addr = "mrfVaCCdDxdt4iAJ5HuTTHFCEC825V84SF"
    ltc_sender_txid = ltc_sender_sendtx(ltc_block_since, ltc_sender_addr, 'regtest', numzero)
    print("ltc_sender_txid:", ltc_sender_txid)
    '''
    '''
    receiver_addr = "mhZ1M56psreihpc7aHBqjbxw6C1BjwJedd"
    block_since = bitcoin_client.btc_getblockcount() - 6
    DH_addr = btc_check_DHaddr(receiver_addr,'bitcoin',block_since, 'regtest')
    print("DH_addr:", DH_addr)
    '''

    '''
    btc_receiver_addr = "mxVbiPxEQTRx1GX5yCrQRjBG7DXe6mVxP1"
    #block_since = litecoin_client.ltc_getblockcount() - 6
    DH_addr = btc_check_DHaddr('Bob.db', btc_receiver_addr, 'regtest')
    print("btc_DHaddr:", DH_addr)
    '''