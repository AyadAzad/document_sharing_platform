# accounts/urls.py
from django.urls import path, include
from . import views
from .views import home

urlpatterns = [
    path('', home, name='home'),
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('accounts/', include('django.contrib.auth.urls')),
    path('send-document/', views.send_document, name='send_document'),
    path('received-documents/', views.received_documents, name='received-documents'),
]
