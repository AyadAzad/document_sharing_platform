from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('home/', views.home, name='home'),
    path('', views.hero, name='hero'),
    path('send-document/', views.send_document, name='send_document'),
    path('received-documents/', views.received_documents, name='received_documents'),
    path('profile/', views.user_information, name='user_profile'),
    path('sent-documents/', views.sent_documents, name='sent_documents'),
    path('about-us/', views.about_us, name='about_us'),
    path('feature/', views.feature, name='feature'),
    path('security/', views.security, name='security'),
    path('contact-us/', views.contact_us, name='contact_us'),
    path('privacy-policy/', views.privacy_policy, name='privacy_policy'),
    path('licensing/', views.licensing, name='licensing'),
]
