from rest_framework import serializers
from .models import CustomUser, UserProfile, WeightRecord, CalorieRecord, SleepRecord
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
import logging

# ロガーを取得
logger = logging.getLogger('django')

# ユーザー登録用シリアライザ
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ('email', 'password')

    def create(self, validated_data):
        # create_user を使うとパスワードは自動でハッシュ化される
        user = CustomUser.objects.create_user(**validated_data)
        return user

    # def create(self, validated_data):
    #     user = CustomUser.objects.create(
    #         email=validated_data['email'],
    #     )
    #     user.set_password(validated_data['password'])
    #     user.save()
    #     return user

# JWT トークン用シリアライザ
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        logger.debug(f"CustomTokenObtainPairSerializer.get_token called for user: {user.email}")
        token = super().get_token(user)
        token['email'] = user.email  # カスタムクレーム
        token['user_id'] = user.id
        return token


# プロフィールシリアライザー
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = '__all__'

# 体重履歴シリアライザー
class WeightRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = WeightRecord
        fields = '__all__'

# カロリー記録シリアライザー
class CalorieRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = CalorieRecord
        fields = '__all__'

# カロリー記録シリアライザー
class SleepRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = SleepRecord
        fields = '__all__'
