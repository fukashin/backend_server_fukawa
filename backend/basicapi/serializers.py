from rest_framework import serializers
from .models import CustomUser

class FirebaseRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'firebase_uid')

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'firebase_uid', 'username', 'date_joined')
        read_only_fields = ('id', 'date_joined')
