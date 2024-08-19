from django.urls import path
from . import views
# from .views import fetch_userinfo

urlpatterns = [
    path('', views.home, name='home'),
    path('callback/', views.callback, name='callback'),
]
