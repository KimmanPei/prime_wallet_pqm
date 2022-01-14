import crypto
import DB_insert
import DB_select


# generate btc or ltc hash collision
def gen_btc_account():
    flag = [0]*65536
    # initial the flag
    cnt = DB_select.flag_initial(flag)
    print("have finished %d keypairs" % (cnt))
    for i in range(cnt,65536):
        while(1):
            sk, pk = crypto.gen_keypair()
            pk_bytes, sk_bytes = crypto.get_byteskeypair(pk, sk)
            pk_script = crypto.get_btc_pkscript(pk, 'regtest')
            hashid_int = crypto.get_hashid(pk_script)
            if flag[hashid_int] == 0:
                DB_insert.btc_target_addr_insert(hashid_int, pk_script, pk_bytes, sk_bytes)
                flag[hashid_int] = 1
                cnt = cnt + 1
                break
        print("%d keypairs have been generated" % (cnt))


def gen_ltc_account():
    flag = [0]*65536
    # initial the flag
    cnt = DB_select.ltc_flag_initial(flag)
    print("have finished %d keypairs" % (cnt))
    for i in range(cnt, 65536):
        while(1):
            sk, pk = crypto.gen_keypair()
            pk_bytes, sk_bytes = crypto.get_byteskeypair(pk, sk)
            pk_script = crypto.get_ltc_pkscript(pk, 'regtest')
            hashid_int = crypto.get_hashid(pk_script)
            if flag[hashid_int] == 0:
                DB_insert.ltc_target_addr_insert(hashid_int, pk_script, pk_bytes, sk_bytes)
                flag[hashid_int] = 1
                cnt = cnt + 1
                break
        print("%d keypairs have been generated" % (cnt))


def gen_eth_account():
    flag = [0]*65536
    # initial the flag
    cnt = DB_select.eth_flag_initial(flag)
    print("have finished %d keypairs" % (cnt))
    for i in range(cnt, 65536):
        while True:
            while True:
                sk, pk = crypto.gen_keypair()
                pk_bytes, sk_bytes = crypto.get_byteskeypair(pk, sk)
                to_addr = crypto.get_eth_address(pk)
                to_addr_hex = to_addr.hex()
                if to_addr_hex[0] != '0':
                    break
            hashid_int = int.from_bytes(to_addr[-2:], "big")
            if flag[hashid_int] == 0:
                # to_addr in database is bytes type and isn't checksum address
                DB_insert.eth_target_addr_insert(hashid_int, to_addr, pk_bytes, sk_bytes)
                flag[hashid_int] = 1
                cnt = cnt + 1
                break
        print("%d keypairs have been generated" % (cnt))


gen_ltc_account()