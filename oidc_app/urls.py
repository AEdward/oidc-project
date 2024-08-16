from django.urls import path
from . import views
# from .views import fetch_userinfo

urlpatterns = [
    path('', views.home, name='home'),
    path('callback/', views.callback, name='callback'),
    path('userinfo/', views.userinfo, name='userinfo'),
    # path('api/fetch-userinfo/', fetch_userinfo, name='fetch_userinfo'),
]
