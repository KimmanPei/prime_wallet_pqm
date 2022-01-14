# article/urls.py

# 引入path
from django.conf.urls import url
from django.urls import path
from django.views.generic import RedirectView

from . import views

# 正在部署的应用的名称
app_name = 'article'

urlpatterns = [
 	# path函数将url映射到视图
 	path('', views.article_welcome, name=''),
    path('article-list/', views.article_list, name='article_list'),

    path('article-welcome/', views.article_welcome, name='article_welcome'),
    # 文章详情
    path('article-detail/<int:id>/', views.article_detail, name='article_detail'),
     # 写文章
    path('article-create/', views.article_create, name='article_create'),

    path('article-mine/', views.article_mine, name='article_mine'),

    path('article-transfer/', views.article_transfer, name='article_transfer'),

    path('article-txrecords/', views.article_txrecords, name='article_txrecords'),

    path('article-ethtx/', views.article_ethtx, name='article_ethtx'),

    path('article-btctx/', views.article_btctx, name='article_btctx'),

    path('article-ltctx/', views.article_ltctx, name='article_ltctx'),

    path('article-bchtx/', views.article_bchtx, name='article_bchtx'),

    path('article-ethat/', views.article_ethat, name='article_ethat'),

    path('article-btcat/', views.article_btcat, name='article_btcat'),

    path('article-ltcat/', views.article_ltcat, name='article_ltcat'),

    path('article-bchat/', views.article_bchat, name='article_bchat'),

    path('article-sendfile/', views.article_sendfile, name='article_sendfile'),

    path('article-receive_text/', views.article_receive_text, name='article_receive_text'),

    path('address/btc.json', views.get_btc_AV, name='get_btc_AV'),

    path('address/ltc.json', views.get_ltc_AV, name='get_ltc_AV'),

    path('address/eth.json', views.get_eth_AV, name='get_eth_AV'),

   # path('/register.json/', views)
    path('index.html', views.index, name='index'),
    # url(r'^(?!/static/.*)(?P<path>.*(?:js|css|img).*)$',RedirectView.as_view(url='/static/%(path)s')),
    url(r'^(?!/static/.*)(?P<path>.*\..*)$',RedirectView.as_view(url='/static/%(path)s')),
    # url(r'^(?P<path>(?:js|css|img)/.*)$', 'serve'),
    # path('address/ltc.json/')
]
