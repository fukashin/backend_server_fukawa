import json
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from .models import CustomUser, UserProfile

class UserRegistrationTest(TestCase):
    """ユーザー登録機能のテスト"""

    def setUp(self):
        """テスト前の準備"""
        self.client = APIClient()
        self.register_url = reverse('register')
        self.user_data = {
            'email': 'test@example.com',
            'password': 'testpassword123',
            'name': 'Test User'
        }

    def test_user_registration_success(self):
        """正常なユーザー登録のテスト"""
        response = self.client.post(
            self.register_url,
            self.user_data,
            format='json'
        )
        
        # レスポンスのステータスコードを確認
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # レスポンスの内容を確認
        self.assertIn('message', response.data)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], self.user_data['email'])
        
        # データベースにユーザーが作成されたことを確認
        self.assertTrue(CustomUser.objects.filter(email=self.user_data['email']).exists())
        
        # ユーザープロフィールが作成されたことを確認
        user = CustomUser.objects.get(email=self.user_data['email'])
        self.assertTrue(UserProfile.objects.filter(user=user).exists())
        
        # プロフィールの内容を確認
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.name, self.user_data['name'])
        self.assertEqual(profile.nickname, self.user_data['email'].split('@')[0])

    def test_user_registration_duplicate_email(self):
        """重複したメールアドレスでの登録テスト"""
        # 最初のユーザーを登録
        self.client.post(
            self.register_url,
            self.user_data,
            format='json'
        )
        
        # 同じメールアドレスで2回目の登録を試みる
        response = self.client.post(
            self.register_url,
            self.user_data,
            format='json'
        )
        
        # 重複エラーが返されることを確認
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    def test_user_registration_invalid_data(self):
        """無効なデータでの登録テスト"""
        # メールアドレスなしでの登録
        invalid_data = {
            'password': 'testpassword123',
            'name': 'Test User'
        }
        
        response = self.client.post(
            self.register_url,
            invalid_data,
            format='json'
        )
        
        # バリデーションエラーが返されることを確認
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        
        # パスワードなしでの登録
        invalid_data = {
            'email': 'test@example.com',
            'name': 'Test User'
        }
        
        response = self.client.post(
            self.register_url,
            invalid_data,
            format='json'
        )
        
        # バリデーションエラーが返されることを確認
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)
