import json

import bitcoin_client
import ether_client
import litecoin_client
import DB_select
import DB_insert


# 获取比特币/莱特币地址和余额
def get_addr_balance(username, coinname):
    db_name = username + '.db'
    if coinname == 'bitcoin':
        AV = bitcoin_client.getall_address_balance(username)
    elif coinname == 'litecoin':
        AV = litecoin_client.getall_address_balance(username)
    elif coinname == 'ether':
        AV = ether_client.list_user_addr(username)
    AV_list = list()
    count = 0
    all_DHaddr_list = DB_select.get_all_DHaddr(db_name, coinname)
    all_spcladdr_list = DB_select.get_all_specialaddr(db_name, coinname)
    if AV:
        for key in AV.keys():
            count += 1
            key_show = key
            if key in all_DHaddr_list:
                key_show = key + "*"
            if key in all_spcladdr_list:
                key_show = key + "^"
            AV_list.append({"id": count, "address": key_show, "balance": AV[key]})
    # print(AV_list)
    return json.dumps(AV_list)


if __name__ == '__main__':
    print(get_addr_balance('Bob', 'bitcoin'))