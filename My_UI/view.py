from django.shortcuts import render, redirect


def article_welcome(request):
    return render(request, 'article/welcome.html')
