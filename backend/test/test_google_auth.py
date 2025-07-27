import json
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from basicapi.models import CustomUser, GoogleAuthInfo, UserProfile

class GoogleAuthTest(TestCase):
    """Google認証機能のテスト"""

    def setUp(self):
        """テスト前の準備"""
        self.client = APIClient()
        self.google_auth_url = reverse('google_auth')
        self.google_token = 'mock_google_token'
        
        # モック用のGoogleユーザー情報
        self.google_user_info = {
            'id': 'google_123456789',
            'email': 'google_user@example.com',
            'name': 'Google User',
            'picture': 'https://example.com/profile.jpg'
        }

    @patch('requests.get')
    def test_google_auth_new_user(self, mock_get):
        """新規ユーザーのGoogle認証テスト"""
        # requestsのgetメソッドをモック化
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = self.google_user_info
        mock_get.return_value = mock_response
        
        # Google認証リクエスト
        response = self.client.post(
            self.google_auth_url,
            {'access_token': self.google_token},
            format='json'
        )
        
        # レスポンスのステータスコードを確認
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # レスポンスの内容を確認
        self.assertIn('message', response.data)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], self.google_user_info['email'])
        self.assertTrue(response.data['is_new_user'])
        
        # データベースにユーザーが作成されたことを確認
        self.assertTrue(CustomUser.objects.filter(email=self.google_user_info['email']).exists())
        
        # Google認証情報が保存されたことを確認
        user = CustomUser.objects.get(email=self.google_user_info['email'])
        self.assertTrue(GoogleAuthInfo.objects.filter(user=user).exists())
        
        # Google認証情報の内容を確認
        google_auth = GoogleAuthInfo.objects.get(user=user)
        self.assertEqual(google_auth.google_id, self.google_user_info['id'])
        self.assertEqual(google_auth.google_email, self.google_user_info['email'])
        self.assertEqual(google_auth.google_name, self.google_user_info['name'])
        self.assertEqual(google_auth.google_picture, self.google_user_info['picture'])
        
        # ユーザープロフィールが作成されたことを確認
        self.assertTrue(UserProfile.objects.filter(user=user).exists())
        
        # プロフィールの内容を確認
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.name, self.google_user_info['name'])
        self.assertEqual(profile.nickname, self.google_user_info['name'])

    @patch('requests.get')
    def test_google_auth_existing_user(self, mock_get):
        """既存ユーザーのGoogle認証テスト"""
        # 既存のユーザーとGoogle認証情報を作成
        user = CustomUser.objects.create_user(
            email=self.google_user_info['email'],
            password='password123'
        )
        
        GoogleAuthInfo.objects.create(
            user=user,
            google_id=self.google_user_info['id'],
            google_email=self.google_user_info['email'],
            google_name=self.google_user_info['name'],
            google_picture=self.google_user_info['picture']
        )
        
        UserProfile.objects.create(
            user=user,
            height=170.0,
            weight=60.0,
            nickname=self.google_user_info['name'],
            name=self.google_user_info['name']
        )
        
        # requestsのgetメソッドをモック化
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = self.google_user_info
        mock_get.return_value = mock_response
        
        # Google認証リクエスト
        response = self.client.post(
            self.google_auth_url,
            {'access_token': self.google_token},
            format='json'
        )
        
        # レスポンスのステータスコードを確認
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # レスポンスの内容を確認
        self.assertIn('message', response.data)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], self.google_user_info['email'])
        self.assertFalse(response.data['is_new_user'])

    @patch('requests.get')
    def test_google_auth_invalid_token(self, mock_get):
        """無効なトークンでのGoogle認証テスト"""
        # requestsのgetメソッドをモック化して無効なトークンをシミュレート
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {'error': 'Invalid token'}
        mock_get.return_value = mock_response
        
        # Google認証リクエスト
        response = self.client.post(
            self.google_auth_url,
            {'access_token': 'invalid_token'},
            format='json'
        )
        
        # 認証失敗のレスポンスを確認
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)

    def test_google_auth_missing_token(self):
        """トークンなしでのGoogle認証テスト"""
        # トークンなしでリクエスト
        response = self.client.post(
            self.google_auth_url,
            {},
            format='json'
        )
        
        # バリデーションエラーが返されることを確認
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
