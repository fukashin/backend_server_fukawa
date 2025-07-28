from django.urls import path
from .views import FirebaseRegisterView, FirebaseAuthView, EmailPasswordAuthView, LogoutView

urlpatterns = [
    path('api/firebase-register/', FirebaseRegisterView.as_view(), name='firebase_register'),
    path('api/firebase-auth/', FirebaseAuthView.as_view(), name='firebase_auth'),
    path('api/email-auth/', EmailPasswordAuthView.as_view(), name='email_auth'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
]
