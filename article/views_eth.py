# article/views.py

# 引入redirect重定向模块
from django.shortcuts import render, redirect
# 引入HttpResponse
from django.http import HttpResponse
# 导入数据模型ArticlePost
from .models import ArticlePost
# 引入刚才定义的ArticlePostForm表单类
from .forms import ArticlePostForm, UserLoginForm
# 引入User模型
from django.contrib.auth.models import User
import bitcoin_client
import bitcoincash_client
import litecoin_client
import DB_insert
import DB_select
import time
import communicate
import ether_client


def article_welcome(request):
    return render(request, 'article/welcome.html')


def article_mine(request):
    return render(request, 'article/mine.html')


def article_transfer(request):
    # 检测当前用户是否登录，若未登录则转至登录界面
    username = request.user.username
    # print("user:", user)
    if not username:
        user_login_form = UserLoginForm()
        context = {'form': user_login_form}
        return render(request, 'userprofile/login.html', context)
    # 判断用户是否提交数据
    if request.method == "POST":
        # 将提交的数据赋值到表单实例中
        transfer_form = request.POST
        # 判断提交的数据是否满足模型的要求
        if username == 'ldw' or 'test':
            if len(request.POST['note']) == 0:  # 接收消息
                is_valid, seed, rule = communicate.check_receive_format(request.POST['from_address'],
                                                                        request.POST['to_address'])
                if is_valid:
                    messages = communicate.receive(seed, rule)
                    return render(request, "article/transfer.html",
                                  {"receive_message": len(messages), "messages": messages})
            else:
                is_valid, seed, rule, info = communicate.check_send_format(request.POST['from_address'],
                                                                           request.POST['to_address'],
                                                                           request.POST['note'])
                # print("is_valid:", is_valid)
                if is_valid:
                    # print("send message")
                    communicate.send(info, seed, rule)
                    return render(request, "article/welcome.html")

        data = dict()
        data['gas'] = 50000
        data['gasPrice'] = 210

        # print("transfer_form:", transfer_form)
        # for itr in transfer_form:
        #     print(itr)
        data['type'] = transfer_form['type']
        data['from_address'] = transfer_form['from_address']
        # print("from_address" + data["from_address"])
        data['to_address'] = transfer_form['to_address']
        # data['unit'] = transfer_form['unit']
        data['value'] = float(transfer_form['value'])
        # data['notes'] = transfer_form['notes']
        # print("data:", data)
        # return render(request, 'article/jump.html')
        try:
            data['type'] = transfer_form['type']
            data['from_address'] = transfer_form['from_address']
            # print("from_address" + data["from_address"])
            data['to_address'] = transfer_form['to_address']
            # data['unit'] = transfer_form['unit']
            data['value'] = float(transfer_form['value'])
            if data['type'] == 'LTC':
                txid = litecoin_client.ui_transfer_litecoin(data["from_address"], data['to_address'], data['value'])
            elif data['type'] == 'BCH':
                txid = bitcoincash_client.ui_transfer_bitcash(data["from_address"], data['to_address'], data['value'])
                # print('bch_txid:', txid)
            elif data['type'] == 'ETH':
                txid = ether_client.ether_ui_transfer(data["from_address"], data['gas'], data['gasPrice'], data['value'], data['to_address'])
            else:
                txid = bitcoin_client.ui_transfer_bitcoin(data["from_address"], data['to_address'], data['value'])
        except:
            error = "sending failed, plz send again"
            return render(request, 'article/transfer.html', {'error': error})
        # 插入数据库
        db_name = "transaction.db"
        user_name = username
        # txid = "4c0fe9158364ce3860390eb17665c92ecc1e84e899708a6e6ac964b69a660202"
        date_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        [Date, Time] = date_time.split()
        value = str(data["value"])
        TYPE = data["type"]
        from_addr = data["from_address"]
        to_addr = data["to_address"]
        DB_insert.insert_history(db_name, user_name, txid, Date, Time, value, TYPE, from_addr, to_addr)
        return render(request, 'article/jump.html')
    return render(request, 'article/transfer.html')


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
    # print("tx_list", tx_list)
    if len(tx_list) > 3:
        tx_list = tx_list[-3:]
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
    # username = request.user.username
    # label = username
    # if request.method == 'POST':
    #     new_addr = ether_client.eth_getnewaddress('1111')  # 这两行待定
    # AV = ether_client.get_ETH_account_addresses()
    # # print(AV)
    # AV_list = list()
    # count = 0
    # if AV:
    #     for key in AV.keys():
    #         count += 1
    #         AV_list.append({"id": count, "address": key, "balance": AV[key]})
    # return render(request, 'article/ethat.html', {"AV_list": AV_list})
    return render(request, 'article/ethat.html')


def article_btcat(request):
    username = request.user.username
    label = username
    if request.method == 'POST':
        new_addr = bitcoin_client.btc_getnewaddress(label)
        bitcoin_client.btc_generatetoaddress(10, new_addr)
        db_name = 'user.db'
        DB_insert.update_num_addr(db_name, username, 'BTC')
    AV = bitcoin_client.get_BTC_account_addresses(label)
    # print(AV)
    AV_list = list()
    count = 0
    if AV:
        for key in AV.keys():
            count += 1
            AV_list.append({"id": count, "address": key, "balance": AV[key]})
    # print(AV_list)
    return render(request, 'article/btcat.html', {"AV_list": AV_list})


def article_ltcat(request):
    username = request.user.username
    label = username
    if request.method == 'POST':
        new_addr = litecoin_client.add_LTC_account_address(label)
        # print("LTC新生成的地址为：", new_addr)
        litecoin_client.ltc_generatetoaddress(10, new_addr)
        db_name = 'user.db'
        DB_insert.update_num_addr(db_name, username, 'LTC')
    AV = litecoin_client.get_LTC_account_address(label)
    AV_list = list()
    count = 0
    for key in AV.keys():
        count += 1
        AV_list.append({"id": count, "address": key, "balance": AV[key]})
    return render(request, 'article/ltcat.html', {"AV_list": AV_list})


def article_bchat(request):
    username = request.user.username
    label = username
    if request.method == 'POST':
        new_addr = bitcoincash_client.add_BCH_account_address(label)
        bitcoincash_client.bch_generatetoaddress(10, new_addr)
        db_name = 'user.db'
        DB_insert.update_num_addr(db_name, username, 'BCH')
    AV = bitcoincash_client.get_BCH_account_addresses(label)
    AV_list = list()
    count = 0
    for key in AV.keys():
        count += 1
        AV_list.append({"id": count, "address": key, "balance": AV[key]})
    return render(request, 'article/bchat.html', {"AV_list": AV_list})


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
        (num_add_btc, num_add_bch, num_add_ltc, num_add_eth) = num_addr[0][1:]
        # num_add_eth = len(ether_client.get_ETH_account_addresses())
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

