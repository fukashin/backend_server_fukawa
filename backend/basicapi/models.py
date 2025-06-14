from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils.timezone import now  # 現在の日時を取得するためのヘルパー関数
import uuid

# カスタムマネージャー
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        extra_fields.setdefault('is_active', True)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  # パスワードをハッシュ化
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)                

# カスタムユーザーモデル
class CustomUser(AbstractBaseUser, PermissionsMixin):
    id = models.AutoField(primary_key=True)  # 自動インクリメントの主キー
    email = models.EmailField(unique=True)  # ユニークなメールアドレス
    password = models.CharField(max_length=128)  # ハッシュ化されたパスワード
    created_at = models.DateTimeField(auto_now_add=True)  # アカウント作成日
    updated_at = models.DateTimeField(auto_now=True)  # アカウント更新日
    last_login = models.DateTimeField(null=True, blank=True)  # アカウント最終ログイン日（nullable）

    is_active = models.BooleanField(default=True)  # アクティブ状態
    is_staff = models.BooleanField(default=False)  # スタッフ状態

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'  # ユーザー名フィールドとして使用
    REQUIRED_FIELDS = []  # スーパーユーザー作成時に必要な追加フィールド

    def __str__(self):
        return self.email
    
# プロフィールテーブル
class UserProfile(models.Model):
    id = models.AutoField(primary_key=True)  # 主キー
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='profile')  # ユーザーID
    height = models.FloatField()  # 身長
    weight = models.FloatField()  # 現在の体重
    nickname = models.CharField(max_length=255)  # ニックネーム
    goal = models.TextField(null=True, blank=True)  # ユーザーの目標（任意）
    created_at = models.DateTimeField(auto_now_add=True)  # プロフィール作成日
    updated_at = models.DateTimeField(auto_now=True)  # プロフィール更新日
    name = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.nickname} ({self.user.email})"

# 体重履歴テーブル
class WeightRecord(models.Model):
    id = models.AutoField(primary_key=True)  # 主キー
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='weight_records')  # ユーザーID
    recorded_at = models.DateField()  # 記録した日付
    weight = models.FloatField()  # 体重（kg）
    created_at = models.DateTimeField(auto_now_add=True)  # レコード作成日時
    updated_at = models.DateTimeField(auto_now=True)  # レコード更新日時
    month = models.IntegerField()  # 月番号（例: 1〜12）
    week = models.IntegerField()  # 週番号（例: 1〜53）
    year = models.IntegerField()  # 年

    def __str__(self):
        return f"{self.user.email} - {self.weight}kg on {self.recorded_at}"

    def save(self, *args, **kwargs):
        # recorded_at がセットされていれば自動計算
        if self.recorded_at:
            self.year  = self.recorded_at.year
            self.month = self.recorded_at.month
            self.week  = self.recorded_at.isocalendar()[1]
        super().save(*args, **kwargs)

# カロリー記録テーブル
class CalorieRecord(models.Model):
    id = models.AutoField(primary_key=True)  # 主キー
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='calorie_records')  # ユーザーID
    recorded_at = models.DateField()  # 記録日
    calorie = models.FloatField()  # カロリー
    total_calorie = models.FloatField(null=True, blank=True)  # その日の合計カロリー（オプション）
    created_at = models.DateTimeField(auto_now_add=True)  # レコード作成日時
    updated_at = models.DateTimeField(auto_now=True)  # レコード更新日時
    category = models.TextField(null=True, blank=True)  # カテゴリ情報（オプション）

    def __str__(self):
        return f"{self.user.email} - {self.calorie}kcal on {self.recorded_at}"

# 睡眠時間記録テーブル
class SleepRecord(models.Model):
    id = models.AutoField(primary_key=True)  # 主キー
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sleep_records')  # ユーザーID
    recorded_at = models.DateField()  # 記録日
    sleep_time = models.FloatField()  # 睡眠時間
    created_at = models.DateTimeField(auto_now_add=True)  # レコード作成日時
    updated_at = models.DateTimeField(auto_now=True)  # レコード更新日時

    def __str__(self):
        return f"{self.user.email} - {self.sleep_time}min on {self.recorded_at}"
