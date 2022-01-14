# article/views.py
import base64
import decimal
# 引入redirect重定向模块

from django.shortcuts import render, redirect
# 引入HttpResponse
from django.http import HttpResponse, HttpResponseRedirect, FileResponse
# 导入数据模型ArticlePost
from django.utils.http import urlquote

import addr_manage
import crypto
import ether_client
import sendmsg
import synchronize
from django.contrib import messages
from .models import ArticlePost
# 引入刚才定义的ArticlePostForm表单类
from .forms import ArticlePostForm, UserLoginForm
# 引入User模型
from django.contrib.auth.models import User
import bitcoin_client
import litecoin_client
import DB_insert
import DB_select
import DB_delete
import time
import communicate
from threading import Thread

def article_welcome(request):
    username = request.user.username
    btc_address = "n2RGHTqKBRZimC2L89MwiGuTiszyYbscEu"
    ltc_address = "mgqotZrWSRnmJU95W49YE68SB2B5BeMieu"
    eth_address = "0x9B66661db7B65792f4cFb0C7114C001Ba974e9A6"  # must be checksum address
    aes_key = bytes.fromhex("4f45d7ffcddaa00b8b13bffdc1727e35")
    session_id = 9
    #sendmsg.receive_secret_msg(username, session_id, aes_key, btc_address, ltc_address, eth_address)
    #thread = Thread(target=sendmsg.receive_secret_msg(username, session_id, aes_key, btc_address, ltc_address, eth_address))
    #thread.start()
    return render(request, 'article/welcome.html')


def article_mine(request):
    return render(request, 'article/mine.html')


def article_transfer(request):
    # 检测当前用户是否登录，若未登录则转至登录界面
    username = request.user.username
    dbname = username + ".db"
    num_zero = 2
    nettype = 'regtest'
    if not username:
        user_login_form = UserLoginForm()
        context = {'form': user_login_form}
        return render(request, 'userprofile/login.html', context)
    # 判断用户是否提交数据
    if request.method == "POST":
        # 将提交的数据赋值到表单实例中
        transfer_form = request.POST
        # 判断提交的数据是否满足模型的要求
        from_addr = transfer_form['from_address']
        to_addr = transfer_form['to_address']
        coin_type = transfer_form['type']
        value = str(float(transfer_form["value"]))
        note = transfer_form['note']
        db_name = "transaction.db"
        if note == "":
            # 获取DH_addr并发起一笔tx，接收地址为DH_addr,判断现在是否为这一操作
            if communicate.check_senderDHaddr_format(from_addr, to_addr, coin_type):
                if coin_type == 'BTC':
                    date_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                    [Date, Time] = date_time.split()
                    txid, DH_addr = synchronize.btc_sender_sendtx(dbname, from_addr, nettype, num_zero, value)
                    if not txid:
                        error = "computing DH_addr failed!"
                        return render(request, 'article/transfer.html', {'error': error})
                    if not DB_select.get_sessionid_by_sendersessionID(dbname, DH_addr):
                         DB_insert.insert_sendersessionID(dbname, DH_addr)
                    DB_insert.insert_history(db_name, username, txid, Date, Time, value, coin_type, from_addr, to_addr)
                    bitcoin_client.btc_importaddress(DH_addr, username)
                    print("txid:", txid)
                    print("DH_addr:", DH_addr)
                    if not DB_select.get_skb_byDHaddr(dbname, 'bitcoin', DH_addr):
                        DB_insert.update_num_addr('user.db', username, 'BTC')
                    return render(request, 'article/jump_DH.html', {'txid': txid, 'DH_addr': DH_addr})
                    #return HttpResponse("<script>alert(""You got a DH address:" + DH_addr + ", and the txid is:" + txid+"\");</script>")
                elif coin_type == 'LTC':
                    date_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                    [Date, Time] = date_time.split()
                    txid, DH_addr = synchronize.ltc_sender_sendtx(dbname, from_addr, 'regtest', num_zero, value)
                    DB_insert.insert_history(db_name, username, txid, Date, Time, value, coin_type, from_addr, to_addr)
                    litecoin_client.ltc_importaddress(DH_addr, username)
                    if not DB_select.get_skb_byDHaddr(dbname, 'litecoin', DH_addr):
                        DB_insert.update_num_addr('user.db', username, 'LTC')
                    if not DB_select.get_skb_byDHaddr(dbname, 'litecoin', DH_addr):
                        DB_insert.update_num_addr('user.db', username, 'LTC')
                    return render(request, 'article/jump_DH.html', {'txid': txid, 'DH_addr': DH_addr})
                elif coin_type == 'ETH':
                    date_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                    [Date, Time] = date_time.split()
                    txid, DH_addr = synchronize.eth_sender_sendtx(username, from_addr, num_zero, value)
                    DB_insert.insert_history(db_name, username, txid, Date, Time, value, coin_type, from_addr, to_addr)
                    if not DB_select.sender_checkethDH_by_DHaddr(dbname, DH_addr):
                        DB_insert.update_num_addr('user.db', username, 'ETH')
                    DB_insert.update_num_addr('user.db', username, 'ETH')
                    return render(request, 'article/jump_DH.html', {'txid': txid, 'DH_addr': DH_addr})
            # 判断是否为接收方核对计算DHaddr
            is_valid, addr_dict = communicate.check_receiverDHaddr_format(from_addr, to_addr)
            if is_valid:
                btc_specialaddr = addr_dict['btcaddr']
                ltc_specialaddr = addr_dict['ltcaddr']
                eth_specialaddr = addr_dict['ethaddr']
                if not DB_select.check_session_DHaddr(dbname, btc_specialaddr, ltc_specialaddr, eth_specialaddr):
                    btc_DH_addr = synchronize.btc_check_DHaddr(dbname, btc_specialaddr, nettype)
                    ltc_DH_addr = synchronize.ltc_check_DHaddr(dbname, ltc_specialaddr, nettype)
                    eth_DH_addr = synchronize.eth_check_DHaddr(dbname, eth_specialaddr)
                    print("btc_DHaddr, ltc_DHaddr, eth_DHaddr:", btc_DH_addr, ltc_DH_addr, eth_DH_addr)
                    if btc_DH_addr and ltc_DH_addr and eth_DH_addr:
                        DB_insert.insert_checkDHaddr(dbname, btc_specialaddr,ltc_specialaddr, eth_specialaddr, btc_DH_addr, ltc_DH_addr,eth_DH_addr)
                        return render(request, 'article/jump_checkDH.html', {'btc_DHaddr': btc_DH_addr, 'ltc_DHaddr': ltc_DH_addr, 'eth_DHaddr':eth_DH_addr})
                    else:
                        error = "checking DH_addr failed!"
                        return render(request, 'article/transfer.html', {'error': error})
                else:
                    btc_DH_addr, ltc_DH_addr, eth_DH_addr=DB_select.get_allcoin_DHaddr(dbname,btc_specialaddr)
                    return render(request, 'article/jump_checkDH.html',
                                  {'btc_DHaddr': btc_DH_addr, 'ltc_DHaddr': ltc_DH_addr, 'eth_DHaddr': eth_DH_addr})
            # 接收消息
            if communicate.check_receivetext_format(from_addr,to_addr):
                btc_DHaddr,ltc_DHaddr, eth_DHaddr=DB_select.get_allcoin_DHaddr(dbname,from_addr)
                session_id=DB_select.get_sessionid_by_checkDHaddr(dbname,btc_DHaddr)
                aeskey=crypto.receive_get_aeskey(dbname,btc_DHaddr,ltc_DHaddr)
                msgbuf, msgtype= sendmsg.receive_secret_msg(username,session_id,aeskey,btc_DHaddr,ltc_DHaddr,eth_DHaddr)
                if not msgbuf:
                    error = "There is no messages"
                    return render(request, 'article/transfer.html', {'error': error})
                new_sessionid = session_id + 1
                DB_insert.update_checkDHaddr(dbname, btc_DHaddr, new_sessionid)
                if msgtype == bytes.fromhex('00'):
                    messages = msgbuf.decode("utf-8")
                    #return render(request, "article/transfer.html", {"receive_message": len(messages), "messages": messages})
                    return render(request, "article/receive_text.html", {"receive_message": len(messages), "messages": messages})
                else:
                    print("yes,received!")
                    file, filename = communicate.rebuild_file(msgtype, msgbuf)
                    response = FileResponse(file)
                    response['Content-Type'] = 'application/octet-stream'
                    response['Content-Disposition'] = "attachment;filename={}".format(urlquote(filename))  # 设置名字
                    DB_delete.delete_session_msg(dbname)
                    DB_delete.delete_raw_msg(dbname)
                    #communicate.delete_file(filename)
                    return response
                    #return render(request, 'article/transfer.html')

            try:
                data = dict()
                data['type'] = transfer_form['type']
                data['from_address'] = transfer_form['from_address']
                # print("from_address" + data["from_address"])
                data['to_address'] = transfer_form['to_address']
                # data['unit'] = transfer_form['unit']
                data['value'] = float(transfer_form['value'])
                if data['type'] == 'LTC':
                    txid = litecoin_client.ui_send_ltctx(dbname, data["from_address"], data['to_address'], data['value'])
                elif data['type'] == 'BCH':
                    pass
                    # txid = bitcoincash_client.ui_transfer_bitcash(data["from_address"], data['to_address'], data['value'])
                elif data['type'] == 'ETH':
                    value_eth = transfer_form['value']
                    txid = ether_client.ui_transfer_ether(username, data["from_address"], data['to_address'], value_eth)
                    print('eth_txid:', txid)
                else:
                    txid = bitcoin_client.ui_send_btctx(dbname, data["from_address"], data['to_address'], data['value'])
            except TypeError as te:
                print(te)
                error = "sending failed, plz send again"
                return render(request, 'article/transfer.html', {'error': error})
            except Exception as e:
                print(e)
                error = "sending failed, plz send again"
                return render(request, 'article/transfer.html', {'error': error})
            # 插入数据库
            user_name = username
            # txid = "4c0fe9158364ce3860390eb17665c92ecc1e84e899708a6e6ac964b69a660202"
            date_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            [Date, Time] = date_time.split()
            value = str(data["value"])
            TYPE = data["type"]
            from_addr = data["from_address"]
            to_addr = data["to_address"]
            DB_insert.insert_history(db_name, user_name, txid, Date, Time, value, TYPE, from_addr, to_addr)
            return render(request, 'article/jump.html',{'txid':txid})

        # 说明要发送隐秘文本消息,fromaddr有三个地址
        is_valid, addrdict = communicate.check_sendtext_format(from_addr, to_addr)
        if is_valid:
            # _, addrdict = communicate.check_sendtext_format(from_addr, to_addr)
            btcaddr = addrdict.get('btcaddr')
            ltcaddr = addrdict.get('ltcaddr')
            ethaddr = addrdict.get('ethaddr')
            aeskey = crypto.get_aeskey(dbname, btcaddr, ltcaddr)
            sender_sessionid = DB_select.get_sessionid_by_sendersessionID(dbname, btcaddr)
            msg_byte = note.encode("utf-8")
            try:
                is_send = sendmsg.send_secret_msg(username, sender_sessionid, aeskey, btcaddr,ltcaddr,ethaddr,msg_byte)
            except Exception as info:
                return render(request, 'article/transfer.html', {'info': info})
            if is_send:
                info = 'sent successfully!'
                new_sessionid = sender_sessionid + 1
                DB_insert.update_sendersessionID(dbname, btcaddr, new_sessionid)
            else:
                info = 'sending failed, plz send again'
            return render(request, 'article/transfer.html', {'info': info})
        # 决定是否要跳转到sendfile页面
        elif communicate.check_sendfile_format(note):
            return render(request, 'article/sendfile.html')
    return render(request, 'article/transfer.html')


def article_receive_text(request):
    username = request.user.username
    dbname = username+'.db'
    if request.method == 'POST':
        print("here")
        DB_delete.delete_raw_msg(dbname)
        DB_delete.delete_session_msg(dbname)
        return render(request, 'article/welcome.html')


def article_sendfile(request):
    username = request.user.username
    dbname = username+'.db'
    if request.method == 'POST':
        file = request.FILES.get("user_file")
        file_name = file.name
        file_byte = base64.b64encode(file.read())
        from_addr=request.POST['from_address']
        to_addr = request.POST['to_address']
        isvalid, dict = communicate.second_check_sendfile_format(from_addr,to_addr,file_name)
        if isvalid:
            btc_DHaddr = dict['btcaddr']
            ltc_DHaddr = dict['ltcaddr']
            eth_DHaddr = dict['ethaddr']
            aeskey = crypto.get_aeskey(dbname, btc_DHaddr, ltc_DHaddr)
            sender_sessionid = DB_select.get_sessionid_by_sendersessionID(dbname, btc_DHaddr)
            msg_type = communicate.get_msgtype(file_name)
            print("msgtype:",msg_type)
            try:
                is_send = sendmsg.send_secret_file(username, sender_sessionid, aeskey, btc_DHaddr, ltc_DHaddr, eth_DHaddr,file_byte,msg_type)
            except Exception as info:
                raise Exception("error:", info)
                # return render(request, 'article/transfer.html', {'info': info})
            if is_send:
                info = 'sent successfully!'
                new_sessionid = sender_sessionid + 1
                DB_insert.update_sendersessionID(dbname, btc_DHaddr, new_sessionid)
            else:
                info = 'sending failed, plz send again'
            return render(request, 'article/transfer.html', {'info': info})
    return render(request, 'article/transfer.html', {'info': "sending failed, plz send again"})


# <td width="600"> currency type </td>
# <td width="600"> from address </td>
# <td width="600"> to address </td>
# <td width="100"> time </td>
# <td width="60"> unit </td>
# <td width="600"> value </td>
def article_txrecords(request):
    # 检测当前用户是否登录，若未登录则转至登录界面
    username = request.user.username
    # print("user:", user)
    if not username:
        user_login_form = UserLoginForm()
        context = {'form': user_login_form}
        return render(request, 'userprofile/login.html', context)
    db_name = 'transaction.db'
    table_name = 'HISTORY'
    tx = DB_select.get_table_detail(db_name, table_name)
    tx_list = DB_select.to_usdict(tx)
    tx_list.reverse()
    # print("tx_list", tx_list)
    if len(tx_list) > 3:
        tx_list = tx_list[0:3]
    return render(request, 'article/txrecords.html', {"tx_list": tx_list})


def article_ethtx(request):
    db_name = 'transaction.db'
    table_name = 'HISTORY'
    cur_type = "ETH"
    tx = DB_select.get_type_detail(db_name, table_name, cur_type)
    tx_list = DB_select.to_usdict(tx)
    return render(request, 'article/ethtx.html', {"tx_list": tx_list})


def article_btctx(request):
    db_name = 'transaction.db'
    table_name = 'HISTORY'
    cur_type = "BTC"
    tx = DB_select.get_type_detail(db_name, table_name, cur_type)
    tx_list = DB_select.to_usdict(tx)
    return render(request, 'article/btctx.html', {"tx_list": tx_list})


def article_ltctx(request):
    db_name = 'transaction.db'
    table_name = 'HISTORY'
    cur_type = "LTC"
    tx = DB_select.get_type_detail(db_name, table_name, cur_type)
    tx_list = DB_select.to_usdict(tx)
    return render(request, 'article/ltctx.html', {"tx_list": tx_list})


def article_bchtx(request):
    db_name = 'transaction.db'
    table_name = 'HISTORY'
    cur_type = "BCH"
    tx = DB_select.get_type_detail(db_name, table_name, cur_type)
    tx_list = DB_select.to_usdict(tx)
    return render(request, 'article/bchtx.html', {"tx_list": tx_list})


def article_ethat(request):
    username = request.user.username
    num_zero = 2
    db_name = username + ".db"
    user_db_name = 'user.db'
    if request.method == 'POST':
        if 'addr_type' in request.POST:
            if request.POST.get('addr_type') == 'special':
                new_addr = crypto.gen_special_ethaddr(num_zero, username)
                DB_insert.update_num_addr(user_db_name, username, 'ETH')
                return HttpResponse("<script>alert(\"You got a special address:" + new_addr + "\");</script>")
            elif request.POST.get('addr_type') == 'general':
                new_addr = ether_client.eth_gen_selfaddress(username)
                DB_insert.update_num_addr(user_db_name, username, 'ETH')
                return HttpResponse("<script>alert(\"You got a general address: " + new_addr + "\");</script>")
    AV = ether_client.list_user_addr(username)
    AV_list=list()
    count = 0
    all_DHaddr_list = DB_select.get_all_eth_DHaddr(db_name)
    print("eth_DHaddr:",all_DHaddr_list)
    all_spcladdr_list = DB_select.get_eth_specialaddr(db_name)
    if AV:
        for key in AV.keys():
            count += 1
            key_show = key
            if all_DHaddr_list:
                if key in all_DHaddr_list:
                    key_show = key + "*"
            if all_spcladdr_list:
                if key in all_spcladdr_list:
                    key_show = key + "^"
            AV_list.append({"id": count, "address": key_show, "balance": AV[key]})
    # print(AV_list)
    return render(request, 'article/ethat.html', {"AV_list": AV_list})


def article_btcat(request):
    username = request.user.username
    label = username
    num_zero = 2
    nettype = 'regtest'
    db_name = username+".db"
    user_db_name = 'user.db'
    if 'addr_type' in request.POST:
        if request.POST.get('addr_type') == 'special':
            new_addr = synchronize.get_btc_receiver_addr(num_zero, nettype, label, db_name)
            DB_insert.update_num_addr(user_db_name, username, 'BTC')
            return HttpResponse("<script>alert(\"You got a special address:"+new_addr+"\");</script>")
        elif request.POST.get('addr_type') == 'general':
            new_addr = crypto.gen_selfaddr(nettype, 'bitcoin', db_name)
            bitcoin_client.btc_importaddress(new_addr, label)
            DB_insert.update_num_addr(user_db_name, username, 'BTC')
            return HttpResponse("<script>alert(\"You got a general address: " + new_addr + "\");</script>")
        #bitcoin_client.btc_generatetoaddress(10, new_addr)
    AV = bitcoin_client.getall_address_balance(label)
    AV_list = list()
    count = 0
    all_DHaddr_list = DB_select.get_all_DHaddr(db_name, 'bitcoin')
    all_spcladdr_list = DB_select.get_all_specialaddr(db_name, 'bitcoin')
    if AV:
        for key in AV.keys():
            count += 1
            key_show = key
            if key in all_DHaddr_list:
                key_show = key+"*"
            if key in all_spcladdr_list:
                key_show = key+"^"
            AV_list.append({"id": count, "address": key_show, "balance": AV[key]})
    # print(AV_list)
    return render(request, 'article/btcat.html', {"AV_list": AV_list})


def article_ltcat(request):
    username = request.user.username
    label = username
    num_zero = 2
    nettype = 'regtest'
    db_name = username + ".db"
    user_db_name = 'user.db'
    if 'addr_type' in request.POST:
        if request.POST.get('addr_type') == 'special':
            new_addr = synchronize.get_ltc_receiver_addr(num_zero, nettype, label, db_name)
            DB_insert.update_num_addr(user_db_name, username, 'LTC')
            return HttpResponse("<script>alert(\"You got a special address:" + new_addr + "\");</script>")
        elif request.POST.get('addr_type') == 'general':
            new_addr = crypto.gen_selfaddr(nettype, 'litecoin', db_name)
            litecoin_client.ltc_importaddress(new_addr, label)
            DB_insert.update_num_addr(user_db_name, username, 'LTC')
            return HttpResponse("<script>alert(\"You got a general address: " + new_addr + "\");</script>")
        # bitcoin_client.btc_generatetoaddress(10, new_addr)
    AV = litecoin_client.getall_address_balance(label)
    AV_list = list()
    count = 0
    all_DHaddr_list = DB_select.get_all_DHaddr(db_name, 'litecoin')
    all_spcladdr_list = DB_select.get_all_specialaddr(db_name, 'litecoin')
    if AV:
        for key in AV.keys():
            count += 1
            key_show = key
            if key in all_DHaddr_list:
                key_show = key + "*"
            if key in all_spcladdr_list:
                key_show = key + "^"
            AV_list.append({"id": count, "address": key_show, "balance": AV[key]})
    return render(request, 'article/ltcat.html', {"AV_list": AV_list})


def article_bchat(request):
    username = request.user.username
    pass


# 视图函数
def article_list(request):
    # 检测当前用户是否登录，若未登录则转至登录界面
    username = request.user.username
    # print("user:", user)
    if not username:
        user_login_form = UserLoginForm()
        context = {'form': user_login_form}
        return render(request, 'userprofile/login.html', context)
    articles = ArticlePost.objects.all()
    # 需要传递给模板（templates）的对象
    context = { 'articles': articles}
    # render函数：载入模板，并返回context对象
    # print("request.method:", request.method)
    # num_add_eth = 0
    # num_add_ltc = len(litecoin_client.get_LTC_account_address(username))
    # num_add_bch = len(bitcoincash_client.get_BCH_account_addresses(username))
    # num_add_btc = len(bitcoin_client.get_BTC_account_addresses(username))
    # num_add_ltc = len(litecoin_client.get_LTC_account_addresses(""))
    # num_add_bch = len(bitcoincash_client.get_BCH_account_addresses(""))
    db_name = 'user.db'
    table_name = 'NUM_ADDR'
    num_addr = DB_select.get_user_detail(db_name, table_name, username)
    if len(num_addr) == 0:
        (num_add_btc, num_add_bch, num_add_ltc, num_add_eth) = (0, 0, 0, 0)
    else:
        (num_add_btc, num_add_bch, num_add_ltc, num_add_eth) = num_addr[0][1:]#第一个字段是用户名，打印的时候要除去
    #num_add_eth = test_client.eth_addressnum()
    context['num_add'] = [num_add_btc, num_add_eth, num_add_bch, num_add_ltc]
    return render(request, 'article/list.html', context)


# 文章详情
def article_detail(request, id):
    # 取出相应的文章
    article = ArticlePost.objects.get(id=id)
    # 需要传递给模板的对象
    context = { 'article': article }
    # 载入模板，并返回context对象
    return render(request, 'article/detail.html', context)


# 写文章的视图
def article_create(request):
    # 判断用户是否提交数据
    if request.method == "POST":
        # 将提交的数据赋值到表单实例中
        article_post_form = ArticlePostForm(data=request.POST)
        # 判断提交的数据是否满足模型的要求
        if article_post_form.is_valid():
            # 保存数据，但暂时不提交到数据库中
            new_article = article_post_form.save(commit=False)
            # 指定数据库中 id=1 的用户为作者
            # 如果你进行过删除数据表的操作，可能会找不到id=1的用户
            # 此时请重新创建用户，并传入此用户的id
            new_article.author = User.objects.get(id=1)
            # 将新文章保存到数据库中
            new_article.save()
            # 完成后返回到文章列表
            return redirect("article:article_list")
        # 如果数据不合法，返回错误信息
        else:
            return HttpResponse("表单内容有误，请重新填写。")
    # 如果用户请求获取数据
    else:
        # 创建表单类实例
        article_post_form = ArticlePostForm()
        # 赋值上下文
        context = { 'article_post_form': article_post_form }
        # 返回模板
        return render(request, 'article/create.html', context)


def get_btc_AV(request):
    username = request.user.username
    ret = addr_manage.get_addr_balance(username, 'bitcoin')
    print(ret)
    return HttpResponse(ret)


def get_ltc_AV(request):
    username = request.user.username
    ret = addr_manage.get_addr_balance(username, 'litecoin')
    print(ret)
    return HttpResponse(ret)


def get_eth_AV(request):
    username = request.user.username
    ret = addr_manage.get_addr_balance(username, 'ether')
    print(ret)
    return HttpResponse(ret)


def index(request):
    return render(request, 'article/index.html')