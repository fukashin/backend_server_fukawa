import json
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from basicapi.models import CustomUser, FirebaseAuthInfo, UserProfile

class FirebaseAuthTest(TestCase):
    """Firebase認証機能のテスト"""

    def setUp(self):
        """テスト前の準備"""
        self.client = APIClient()
        self.firebase_auth_url = reverse('firebase_auth')
        self.firebase_token = 'mock_firebase_token'
        
        # モック用のFirebaseユーザー情報
        self.firebase_uid = 'firebase_123456789'
        self.firebase_email = 'firebase_user@example.com'
        self.firebase_name = 'Firebase User'
        self.firebase_photo_url = 'https://example.com/firebase_profile.jpg'
        self.provider_id = 'google.com'

    @patch('firebase_admin.auth.verify_id_token')
    @patch('firebase_admin.auth.get_user')
    def test_firebase_auth_new_user(self, mock_get_user, mock_verify_token):
        """新規ユーザーのFirebase認証テスト"""
        # Firebase Admin SDKのモック設定
        mock_verify_token.return_value = {
            'uid': self.firebase_uid,
            'firebase': {'sign_in_provider': self.provider_id}
        }
        
        # Firebaseユーザーオブジェクトのモック
        mock_user = MagicMock()
        mock_user.uid = self.firebase_uid
        mock_user.email = self.firebase_email
        mock_user.display_name = self.firebase_name
        mock_user.photo_url = self.firebase_photo_url
        mock_get_user.return_value = mock_user
        
        # Firebase認証リクエスト
        response = self.client.post(
            self.firebase_auth_url,
            {'id_token': self.firebase_token},
            format='json'
        )
        
        # レスポンスのステータスコードを確認
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # レスポンスの内容を確認
        self.assertIn('message', response.data)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], self.firebase_email)
        self.assertTrue(response.data['is_new_user'])
        
        # データベースにユーザーが作成されたことを確認
        self.assertTrue(CustomUser.objects.filter(email=self.firebase_email).exists())
        
        # Firebase認証情報が保存されたことを確認
        user = CustomUser.objects.get(email=self.firebase_email)
        self.assertTrue(FirebaseAuthInfo.objects.filter(user=user).exists())
        
        # Firebase認証情報の内容を確認
        firebase_auth = FirebaseAuthInfo.objects.get(user=user)
        self.assertEqual(firebase_auth.firebase_uid, self.firebase_uid)
        self.assertEqual(firebase_auth.firebase_email, self.firebase_email)
        self.assertEqual(firebase_auth.firebase_name, self.firebase_name)
        self.assertEqual(firebase_auth.firebase_picture, self.firebase_photo_url)
        self.assertEqual(firebase_auth.provider_id, self.provider_id)
        
        # ユーザープロフィールが作成されたことを確認
        self.assertTrue(UserProfile.objects.filter(user=user).exists())
        
        # プロフィールの内容を確認
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.name, self.firebase_name)
        self.assertEqual(profile.nickname, self.firebase_name)

    @patch('firebase_admin.auth.verify_id_token')
    @patch('firebase_admin.auth.get_user')
    def test_firebase_auth_existing_user(self, mock_get_user, mock_verify_token):
        """既存ユーザーのFirebase認証テスト"""
        # 既存のユーザーとFirebase認証情報を作成
        user = CustomUser.objects.create_user(
            email=self.firebase_email,
            password='password123'
        )
        
        FirebaseAuthInfo.objects.create(
            user=user,
            firebase_uid=self.firebase_uid,
            firebase_email=self.firebase_email,
            firebase_name=self.firebase_name,
            firebase_picture=self.firebase_photo_url,
            provider_id=self.provider_id
        )
        
        UserProfile.objects.create(
            user=user,
            height=170.0,
            weight=60.0,
            nickname=self.firebase_name,
            name=self.firebase_name
        )
        
        # Firebase Admin SDKのモック設定
        mock_verify_token.return_value = {
            'uid': self.firebase_uid,
            'firebase': {'sign_in_provider': self.provider_id}
        }
        
        # Firebaseユーザーオブジェクトのモック
        mock_user = MagicMock()
        mock_user.uid = self.firebase_uid
        mock_user.email = self.firebase_email
        mock_user.display_name = self.firebase_name
        mock_user.photo_url = self.firebase_photo_url
        mock_get_user.return_value = mock_user
        
        # Firebase認証リクエスト
        response = self.client.post(
            self.firebase_auth_url,
            {'id_token': self.firebase_token},
            format='json'
        )
        
        # レスポンスのステータスコードを確認
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # レスポンスの内容を確認
        self.assertIn('message', response.data)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], self.firebase_email)
        self.assertFalse(response.data['is_new_user'])

    @patch('firebase_admin.auth.verify_id_token')
    def test_firebase_auth_invalid_token(self, mock_verify_token):
        """無効なトークンでのFirebase認証テスト"""
        # 無効なトークンをシミュレート
        mock_verify_token.side_effect = Exception('Invalid token')
        
        # Firebase認証リクエスト
        response = self.client.post(
            self.firebase_auth_url,
            {'id_token': 'invalid_token'},
            format='json'
        )
        
        # 認証失敗のレスポンスを確認
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)

    def test_firebase_auth_missing_token(self):
        """トークンなしでのFirebase認証テスト"""
        # トークンなしでリクエスト
        response = self.client.post(
            self.firebase_auth_url,
            {},
            format='json'
        )
        
        # バリデーションエラーが返されることを確認
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
