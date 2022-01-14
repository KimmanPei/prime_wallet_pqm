import json

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse

import create_tables
from .forms import UserLoginForm, UserRegisterForm
from django.contrib.auth.models import User
import DB_insert

# Create your views here.


def user_login(request):
    if request.method == 'POST':
        user_login_form = UserLoginForm(data=request.POST)
        if user_login_form.is_valid():
            # .cleaned_data 清洗出合法数据
            data = user_login_form.cleaned_data
            # 检验账号、密码是否正确匹配数据库中的某个用户
            # 如果均匹配则返回这个 user 对象
            user = authenticate(username=data['username'], password=data['password'])
            if user:
                username = data['username']
                passwd = data['password']
                print(username, passwd)
                # 将用户数据保存在 session 中，即实现了登录动作
                login(request, user)
                return redirect("article:article_welcome")
            else:
                user_login_form = UserLoginForm()
                context = dict()
                context['form'] = user_login_form
                context['error'] = "Wrong password or username, plz try again."
                return render(request, 'userprofile/login.html', context)
                # return HttpResponse("Wrong password or username, plz try again.")
        else:
            user_login_form = UserLoginForm()
            context = dict()
            context['form'] = user_login_form
            context['error'] = "Illegal password or username!"
            return render(request, 'userprofile/login.html', context)
            # return HttpResponse("Illegal password or username!")
    elif request.method == 'GET':
        # print("请求方式为GET")
        user_login_form = UserLoginForm()
        context = {'form': user_login_form}
        return render(request, 'userprofile/login.html', context)
    else:
        return HttpResponse("请使用GET或POST请求数据")


def login_test(request):
    if request.method == 'GET':
        # print("请求方式为GET")
        user_login_form = UserLoginForm()
        context = {'form': user_login_form}
        username = request.GET.get('username')
        password = request.GET.get('password')
        user = authenticate(username=username, password=password)
        print(username, password)
        '''
        if user:
            # 将用户数据保存在 session 中，即实现了登录动作
            login(request, user)
            id = 1
        else:
            return HttpResponse("no")
        '''
        dic = {'username': username, 'id': 1}
        ret = json.dumps(dic)
        print(ret)
        # return HttpResponse("ok")
        return HttpResponse(json.dumps(dic))
    else:
        return HttpResponse("请使用GET或POST请求数据")


# 用户退出
def user_logout(request):
    logout(request)
    return redirect("article:article_welcome")


def user_secret(request):
    return render(request,"userprofile/secret.html")


# 用户注册
def user_register(request):
    if request.method == 'POST':
        data = request.POST
        user_register_form = UserRegisterForm(data)
        if user_register_form.is_valid():
            new_user = user_register_form.save(commit=False)
            # 设置密码
            new_user.set_password(user_register_form.cleaned_data['password'])
            new_user.save()
            # 保存好数据后立即登录并返回博客列表页面
            login(request, new_user)
            db_name = 'user.db'
            DB_insert.insert_num_addr(db_name, data['username'], '0', '0', '0', '0')
            db_user_name = data['username']+".db"
            f = open(db_user_name, "w+")
            create_tables.create_usersendmsg_table(data['username'])
            return redirect("article:article_list")
        else:
            user_register_form = UserRegisterForm()
            context = dict()
            context['form'] = user_register_form
            # print('data:', data)
            # context['error'] = "Wrong register form, plz try again."
            if User.objects.filter(username=data['username']):
                context['error'] = "This username has been exists, plz use another one."
            elif data['password'] != data['password2'] :
                context['error'] = "These two passwords are different, plz try again."
            else:
                context['error'] = "Wrong email form, plz input a right one."
            return render(request, 'userprofile/register.html', context)
            # return HttpResponse("Wrong register form, plz try again.")
    elif request.method == 'GET':
        user_register_form = UserRegisterForm()
        context = { 'form': user_register_form }
        return render(request, 'userprofile/register.html', context)
    else:
        return HttpResponse("请使用GET或POST请求数据")


def register_test(request):
    if request.method == 'POST':
        data = request.POST
        user_register_form = UserRegisterForm(data)
        if user_register_form.is_valid():
            new_user = user_register_form.save(commit=False)
            # 设置密码
            new_user.set_password(user_register_form.cleaned_data['password'])
            new_user.save()
            # 保存好数据后立即登录并返回博客列表页面
            login(request, new_user)
            db_name = 'user.db'
            # DB_insert.insert_num_addr(db_name, data['username'], '0', '0', '0', '0')
            db_user_name = data['username']+".db"
            f = open(db_user_name, "w+")
            create_tables.create_usersendmsg_table(data['username'])
            return redirect("article:article_list")
        else:
            user_register_form = UserRegisterForm()
            context = dict()
            context['form'] = user_register_form

            # print('data:', data)
            # context['error'] = "Wrong register form, plz try again."
            if User.objects.filter(username=data['username']):
                context['error'] = "This username has been exists, plz use another one."
            elif data['password'] != data['password2'] :
                context['error'] = "These two passwords are different, plz try again."
            else:
                context['error'] = "Wrong email form, plz input a right one."
            return render(request, 'userprofile/register.html', context)
            # return HttpResponse("Wrong register form, plz try again.")
    elif request.method == 'GET':
        user_register_form = UserRegisterForm()
        context = {'form': user_register_form}
        data = request.GET.get('username')
        user_register_form = UserRegisterForm(data)
        if user_register_form.is_valid():
            new_user = user_register_form.save(commit=False)
            # 设置密码
            new_user.set_password(user_register_form.cleaned_data['password'])
            new_user.save()
            # 保存好数据后立即登录并返回博客列表页面
            login(request, new_user)
        return render(request, 'userprofile/register.html', context)
    else:
        return HttpResponse("请使用GET或POST请求数据")


if __name__ == '__main__':
    dic = {'username': "alice", 'id': 3}
    ret = json.dumps(dic)
    print(ret)