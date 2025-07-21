import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status,viewsets
from rest_framework_simplejwt.views import TokenRefreshView as BaseTokenRefreshView
from rest_framework_simplejwt.views import TokenObtainPairView as BaseTokenObtainPairView
from .models import UserProfile, WeightRecord, CalorieRecord, SleepRecord, GoogleAuthInfo, CustomUser
from .serializers import RegisterSerializer, CustomTokenObtainPairSerializer, UserProfileSerializer, WeightRecordSerializer, CalorieRecordSerializer, SleepRecordSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.backends import TokenBackend
from django.conf import settings
import datetime as _dt     # ★ これを追加
import requests
from django.utils import timezone
from django.db import transaction

# ログ設定
logger = logging.getLogger(__name__)

# ユーザー登録用ビュー
class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                
                # ユーザープロフィールを作成
                # デフォルト値を設定
                UserProfile.objects.create(
                    user=user,
                    height=170.0,  # デフォルト身長
                    weight=60.0,   # デフォルト体重
                    nickname=user.email.split('@')[0],  # メールアドレスの@前をニックネームに
                    name=request.data.get('name', user.email.split('@')[0])  # nameパラメータがあれば使用、なければニックネームと同じ
                )
                
                # ユーザー登録後、トークンを生成
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)
                
                # レスポンスにトークンを含める
                response = Response(
                    {
                        "message": "User registered successfully!",
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "user": {
                            "email": user.email,
                            "id": user.id
                        }
                    },
                    status=status.HTTP_201_CREATED
                )
                
                # HttpOnlyなCookieにトークンを設定
                response.set_cookie(
                    key='access_token',
                    value=access_token,
                    httponly=True,
                    secure=False,
                    max_age=3600,
                    path='/',
                )
                response.set_cookie(
                    key='refresh_token',
                    value=refresh_token,
                    httponly=True,
                    secure=False,
                    max_age=86400,
                    path='/',
                )
                
                return response
            except Exception as e:
                logger.error(f"Error during user registration: {e}", exc_info=True)
                return Response(
                    {"error": "An unexpected error occurred during registration."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        # エラー内容をログに記録
        logger.warning(f"Validation failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# JWT トークン発行ビュー
class CustomTokenObtainPairView(BaseTokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        # リクエストデータを元にシリアライザで認証処理とトークン生成を行う
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        tokens = serializer.validated_data  # tokensは {'access': <token>, 'refresh': <token>} の形式

        # ユーザー情報を取得
        user = serializer.user

        # 成功レスポンスを作成（トークンをレスポンスボディに含める）
        response = Response(
            {
                "message": "Logged in successfully.",
                "access_token": tokens['access'],
                "refresh_token": tokens['refresh'],
                "user": {
                    "email": user.email,
                    "id": user.id
                }
            },
            status=status.HTTP_200_OK
        )

        # HttpOnlyなCookieにアクセストークンを設定
        response.set_cookie(
            key='access_token',
            value=tokens['access'],
            httponly=True,           # JavaScriptからアクセス不可でXSS対策
            secure=False,             # HTTPS環境でのみ有効（開発時はFalseにする場合も）
            # samesite='Lax',          # CSRF対策に有効（必要に応じて調整）
            max_age=3600,             # Cookieの有効期限（秒）
            path='/',
        )

        # HttpOnlyなCookieにリフレッシュトークンを設定（必要な場合）
        response.set_cookie(
            key='refresh_token',
            value=tokens['refresh'],
            httponly=True,
            secure=False,
            # samesite='Lax',
            max_age=86400            # 例として24時間有効
        )

        return response
    #ログアウト 
class LogoutView(APIView):
    def post(self, request):
        response = Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)
        response.delete_cookie('access_token')  # クッキーの削除
        response.delete_cookie('refresh_token')  # クッキーの削除
        return response


# プロフィールビューセット
class UserProfileViewSet(viewsets.ModelViewSet):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # 認証されたユーザーのプロフィールのみを返す
        user = self.request.user
        return UserProfile.objects.filter(user=user)
    
    def retrieve(self, request, *args, **kwargs):
        # PKではなくユーザーIDでプロフィールを取得できるようにする
        try:
            # URLのpkパラメータがユーザーIDの場合
            user_id = kwargs.get('pk')
            if user_id and user_id.isdigit():
                user_id = int(user_id)
                # 自分のプロフィールのみアクセス可能
                if user_id == request.user.id:
                    profile = UserProfile.objects.get(user_id=user_id)
                    serializer = self.get_serializer(profile)
                    return Response(serializer.data)
                else:
                    return Response({"detail": "他のユーザーのプロフィールにはアクセスできません。"}, 
                                    status=status.HTTP_403_FORBIDDEN)
            return super().retrieve(request, *args, **kwargs)
        except UserProfile.DoesNotExist:
            return Response({"detail": "プロフィールが見つかりません。"}, 
                            status=status.HTTP_404_NOT_FOUND)
    
    def update(self, request, *args, **kwargs):
        # PKではなくユーザーIDでプロフィールを更新できるようにする
        try:
            # URLのpkパラメータがユーザーIDの場合
            user_id = kwargs.get('pk')
            if user_id and user_id.isdigit():
                user_id = int(user_id)
                # 自分のプロフィールのみアクセス可能
                if user_id == request.user.id:
                    profile = UserProfile.objects.get(user_id=user_id)
                    serializer = self.get_serializer(profile, data=request.data, partial=True)
                    if serializer.is_valid():
                        serializer.save()
                        return Response(serializer.data)
                    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({"detail": "他のユーザーのプロフィールは更新できません。"}, 
                                    status=status.HTTP_403_FORBIDDEN)
            return super().update(request, *args, **kwargs)
        except UserProfile.DoesNotExist:
            return Response({"detail": "プロフィールが見つかりません。"}, 
                            status=status.HTTP_404_NOT_FOUND)
    
    def partial_update(self, request, *args, **kwargs):
        # PATCHメソッド用
        return self.update(request, *args, **kwargs)

# 体重履歴ビューセット
class WeightRecordViewSet(viewsets.ModelViewSet):
    serializer_class = WeightRecordSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # 認証されたユーザーの体重記録のみを返す
        user = self.request.user
        return WeightRecord.objects.filter(user=user)

# カロリー記録ビューセット
class CalorieRecordViewSet(viewsets.ModelViewSet):
    serializer_class = CalorieRecordSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # 認証されたユーザーのカロリー記録のみを返す
        user = self.request.user
        return CalorieRecord.objects.filter(user=user)

# 睡眠記録ビューセット
class SleepRecordViewSet(viewsets.ModelViewSet):
    serializer_class = SleepRecordSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # 認証されたユーザーの睡眠記録のみを返す
        user = self.request.user
        return SleepRecord.objects.filter(user=user)


class AuthStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        return Response({
            "detail": "Authenticated",
            "user": request.user.email  # usernameではなくemailを使用
        }, status=status.HTTP_200_OK)

class CookieTokenRefreshView(BaseTokenRefreshView):
    def post(self, request, *args, **kwargs):
        # Cookie からリフレッシュトークンを取得
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return Response({"error": "Refresh token not found."}, status=status.HTTP_400_BAD_REQUEST)

        # ここでは、リクエストデータではなく Cookie から取得したトークンを使ってシリアライザで検証
        serializer = self.get_serializer(data={'refresh': refresh_token})
        serializer.is_valid(raise_exception=True)
        new_access_token = serializer.validated_data['access']

        # 新しいアクセストークンをセットしたレスポンスを返す
        response = Response({"message": "Token refreshed successfully."}, status=status.HTTP_200_OK)
        response.set_cookie(
            key='access_token',
            value=new_access_token,
            httponly=True,
            secure=False,       # 開発環境では False、本番では True
            max_age=3600,
            path='/',
        )
        return response

class CookieUserInfoView(APIView):
    """
    HttpOnly Cookie に格納されたアクセストークンを検証し、
    トークンのペイロードからユーザーIDを取得して返すビュー
    """
    def get(self, request, *args, **kwargs):
        # Cookie からアクセストークンを取得
        access_token = request.COOKIES.get('access_token')
        if not access_token:
            return Response({"error": "Access token not found."},
                            status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # SimpleJWT の TokenBackend を使ってトークンの検証・デコード
            token_backend = TokenBackend(
                algorithm=settings.SIMPLE_JWT['ALGORITHM'],
                signing_key=settings.SECRET_KEY  # または settings.SIMPLE_JWT['SIGNING_KEY'] があればそちらを使用
            )
            token_data = token_backend.decode(access_token, verify=True)
        except Exception as e:
            return Response({"error": "Invalid token", "details": str(e)},
                            status=status.HTTP_401_UNAUTHORIZED)
        
        # ペイロードからユーザーIDを取得（ログイン時にトークンに含めた情報）
        user_id = token_data.get('user_id')
        if not user_id:
            return Response({"error": "User ID not found in token."},
                            status=status.HTTP_401_UNAUTHORIZED)
        
        return Response({"user_id": user_id, "message": "Token is valid. User authenticated."},
                        status=status.HTTP_200_OK)

class StandardUserInfoView(APIView):
    """
    標準的なJWT認証（Authorizationヘッダー）を使用してユーザー情報を取得するビュー
    フロントエンドとの互換性のために追加
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        user = request.user
        return Response({
            "user_id": user.id,
            "email": user.email,
            "message": "Token is valid. User authenticated."
        }, status=status.HTTP_200_OK)

class DailyRecordUpsertAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        data = request.data

        # ────────────────────────────────────────────────
        # 1. recorded_at を date 型に変換（必須）
        # ────────────────────────────────────────────────
        date_str = data.get("recorded_at")
        if not date_str:
            return Response({"detail": "`recorded_at` は必須です"},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            recorded_at = _dt.date.fromisoformat(date_str)
        except ValueError:
            return Response({"detail": "日付フォーマットは YYYY‑MM‑DD で指定してください"},
                            status=status.HTTP_400_BAD_REQUEST)

        # ────────────────────────────────────────────────
        # 2. weight / sleep の取得と簡易バリデーション
        # ────────────────────────────────────────────────
        weight = data.get("weight")
        sleep  = data.get("sleep_time")

        if weight is None and sleep is None:
            return Response({"detail": "`weight` か `sleep_time` のどちらかは必要です"},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            weight = float(weight) if weight is not None else None
        except (TypeError, ValueError):
            return Response({"detail": "`weight` は数値で指定してください"},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            sleep = float(sleep) if sleep is not None else None
        except (TypeError, ValueError):
            return Response({"detail": "`sleep_time` は数値で指定してください"},
                            status=status.HTTP_400_BAD_REQUEST)

        # ────────────────────────────────────────────────
        # 3. Upsert
        # ────────────────────────────────────────────────
        result  = {}
        created_any = False

        if weight is not None:
            weight_obj, created = WeightRecord.objects.update_or_create(
                user=user,
                recorded_at=recorded_at,
                defaults={"weight": weight},
            )
            created_any |= created
            result["weight_record"] = WeightRecordSerializer(weight_obj).data

        if sleep is not None:
            sleep_obj, created = SleepRecord.objects.update_or_create(
                user=user,
                recorded_at=recorded_at,
                defaults={"sleep_time": sleep},
            )
            created_any |= created
            result["sleep_record"] = SleepRecordSerializer(sleep_obj).data

        # ────────────────────────────────────────────────
        # 4. 応答
        # ────────────────────────────────────────────────
        return Response(
            result,
            status=status.HTTP_201_CREATED if created_any else status.HTTP_200_OK,
        )

# Google認証ビュー
class GoogleAuthView(APIView):
    """
    Google認証トークンを受け取り、ユーザーの登録/ログインを処理するビュー
    """
    
    def post(self, request, *args, **kwargs):
        try:
            # リクエストからGoogleトークンを取得
            google_token = request.data.get('access_token')
            if not google_token:
                return Response(
                    {"error": "Google access token is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # GoogleのAPIを使ってトークンを検証し、ユーザー情報を取得
            google_user_info = self._verify_google_token(google_token)
            if not google_user_info:
                return Response(
                    {"error": "Invalid Google token"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # トランザクション内でユーザー処理を実行
            with transaction.atomic():
                user, is_new_user = self._get_or_create_user(google_user_info, google_token)
                
                # JWTトークンを生成
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)
                
                # レスポンスを作成
                response_data = {
                    "message": "Google authentication successful",
                    "is_new_user": is_new_user,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "google_name": google_user_info.get('name'),
                        "google_picture": google_user_info.get('picture')
                    }
                }
                
                response = Response(response_data, status=status.HTTP_200_OK)
                
                # HttpOnlyなCookieにトークンを設定
                response.set_cookie(
                    key='access_token',
                    value=access_token,
                    httponly=True,
                    secure=False,  # 開発環境では False
                    max_age=3600,
                    path='/',
                )
                response.set_cookie(
                    key='refresh_token',
                    value=refresh_token,
                    httponly=True,
                    secure=False,
                    max_age=86400,
                    path='/',
                )
                
                return response
                
        except Exception as e:
            logger.error(f"Google authentication error: {e}", exc_info=True)
            return Response(
                {"error": "Authentication failed"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _verify_google_token(self, token):
        """
        GoogleのAPIを使ってトークンを検証し、ユーザー情報を取得
        """
        try:
            # Google OAuth2 APIを使ってトークンを検証
            response = requests.get(
                f'https://www.googleapis.com/oauth2/v1/userinfo?access_token={token}',
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Google token verification failed: {response.status_code}")
                return None
                
        except requests.RequestException as e:
            logger.error(f"Google API request failed: {e}")
            return None
    
    def _get_or_create_user(self, google_user_info, google_token):
        """
        Googleユーザー情報を基にユーザーを取得または作成
        """
        google_id = google_user_info.get('id')
        google_email = google_user_info.get('email')
        google_name = google_user_info.get('name', '')
        google_picture = google_user_info.get('picture', '')
        
        # Google認証情報でユーザーを検索
        try:
            google_auth = GoogleAuthInfo.objects.get(google_id=google_id)
            user = google_auth.user
            is_new_user = False
            
            # 既存ユーザーのGoogle認証情報を更新
            google_auth.access_token = google_token
            google_auth.google_name = google_name
            google_auth.google_picture = google_picture
            google_auth.token_expires_at = timezone.now() + timezone.timedelta(hours=1)
            google_auth.save()
            
        except GoogleAuthInfo.DoesNotExist:
            # 新規ユーザーの場合
            is_new_user = True
            
            # メールアドレスで既存ユーザーを検索
            try:
                user = CustomUser.objects.get(email=google_email)
                # 既存ユーザーにGoogle認証情報を追加
            except CustomUser.DoesNotExist:
                # 完全に新規のユーザーを作成
                user = CustomUser.objects.create_user(
                    email=google_email,
                    password=None  # Googleログインなのでパスワードは不要
                )
                
                # デフォルトプロフィールを作成
                UserProfile.objects.create(
                    user=user,
                    height=170.0,
                    weight=60.0,
                    nickname=google_name or google_email.split('@')[0],
                    name=google_name or google_email.split('@')[0]
                )
            
            # Google認証情報を作成
            GoogleAuthInfo.objects.create(
                user=user,
                google_id=google_id,
                google_email=google_email,
                google_name=google_name,
                google_picture=google_picture,
                access_token=google_token,
                token_expires_at=timezone.now() + timezone.timedelta(hours=1)
            )
        
        # 最終ログイン時刻を更新
        user.last_login = timezone.now()
        user.save()
        
        return user, is_new_user

# Google認証状態確認ビュー
class GoogleAuthStatusView(APIView):
    """
    現在のユーザーのGoogle認証状態を確認するビュー
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        user = request.user
        
        try:
            google_auth = GoogleAuthInfo.objects.get(user=user)
            return Response({
                "is_google_authenticated": True,
                "google_email": google_auth.google_email,
                "google_name": google_auth.google_name,
                "google_picture": google_auth.google_picture,
                "token_valid": google_auth.is_token_valid()
            }, status=status.HTTP_200_OK)
            
        except GoogleAuthInfo.DoesNotExist:
            return Response({
                "is_google_authenticated": False
            }, status=status.HTTP_200_OK)
