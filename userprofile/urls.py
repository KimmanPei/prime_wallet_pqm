from django.urls import path
from . import views

app_name = 'userprofile'

urlpatterns = [
    # 用户登录
    path('login/', views.user_login, name='login'),
    # 用户退出
    path('logout/', views.user_logout, name='logout'),
     # 用户注册
    path('register/', views.user_register, name='register'),

    path('secret/', views.user_secret, name='secret'),

    # path('/login/', views.user_login, name='login'),
    # path('login_test/', views.login_test, name='login_test'),

    #path('register.json/', views.login_test, name='test_login')

    path('register.json/', views.register_test, name='register')

]