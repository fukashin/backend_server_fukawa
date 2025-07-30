from django.urls import path
from .views import FirebaseRegisterView, FirebaseAuthView, EmailPasswordAuthView, LogoutView

urlpatterns = [
    path('firebase-register/', FirebaseRegisterView.as_view(), name='firebase_register'),
    path('firebase-auth/', FirebaseAuthView.as_view(), name='firebase_auth'),
    path('email-auth/', EmailPasswordAuthView.as_view(), name='email_auth'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
