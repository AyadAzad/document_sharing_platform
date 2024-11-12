from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.home, name='home'),
    path('send-document/', views.send_document, name='send_document'),
    path('received-documents/', views.received_documents, name='received_documents'),
]
