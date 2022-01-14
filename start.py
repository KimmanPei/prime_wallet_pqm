import os
from bitcoin_client import *
import threading
from threading import Thread
import sendmsg

def start_run():
    path = os.getcwd()  # 获取当前路径
    os.chdir(path)  # 命令行移至当前路径
    os.system("python manage.py runserver")


def receive_msg():
    btc_address = "n2RGHTqKBRZimC2L89MwiGuTiszyYbscEu"
    ltc_address = "mgqotZrWSRnmJU95W49YE68SB2B5BeMieu"
    eth_address = "0x9B66661db7B65792f4cFb0C7114C001Ba974e9A6"  # must be checksum address
    aes_key = bytes.fromhex("4f45d7ffcddaa00b8b13bffdc1727e35")
    username = 'Bob'
    session_id = 9
    sendmsg.receive_secret_msg(username, session_id, aes_key, btc_address, ltc_address, eth_address)
    print("have done")

if __name__ == '__main__':
    start_run()
    '''
    threads = []
    threads.append(Thread(target=start_run))
    threads.append(Thread(target=receive_msg()))
    threads[0].start()
    threads[1].start()
    '''
    # 主程序
    # t_run = threading.Thread(target=start_run)
    # t_btc = threading.Thread(target=btc_start)
    # t_ltc = threading.Thread(target=ltc_start)
    # t_bch = threading.Thread(target=bch_start)
    # t_run.start()
    # t_btc.start()
    # t_ltc.start()
    # t_bch.start()

