import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status,viewsets
from rest_framework_simplejwt.views import TokenRefreshView as BaseTokenRefreshView
from rest_framework_simplejwt.views import TokenObtainPairView as BaseTokenObtainPairView
from .models import UserProfile, WeightRecord, CalorieRecord, SleepRecord, CustomUser, FirebaseAuthInfo
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
import firebase_admin
from firebase_admin import credentials, auth

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

# Firebase Admin SDKの初期化
from django.conf import settings

# テスト時にFirebase Admin SDKの初期化をスキップするオプション
if not getattr(settings, 'FIREBASE_ADMIN_SKIP_INIT', False):
    try:
        # Firebase Admin SDKが既に初期化されているかチェック
        firebase_admin.get_app()
    except ValueError:
        # 初期化されていない場合は初期化
        # 本番環境では、サービスアカウントのキーファイルを使用することを推奨
        # ここではアプリケーションのデフォルト認証情報を使用
        try:
            cred = credentials.ApplicationDefault()
            firebase_admin.initialize_app(cred)
            logger.info("Firebase Admin SDKが初期化されました")
        except Exception as e:
            logger.warning(f"Firebase Admin SDKの初期化に失敗しました: {e}")

# Firebase認証ビュー
class FirebaseAuthView(APIView):
    """
    Firebase IDトークンを受け取り、ユーザーの登録/ログインを処理するビュー
    """
    
    def post(self, request, *args, **kwargs):
        try:
            logger.info("Firebase認証リクエストを受信しました")
            
            # リクエストからFirebase IDトークンを取得
            id_token = request.data.get('id_token')
            if not id_token:
                logger.warning("Firebase IDトークンが提供されていません")
                return Response(
                    {"error": "Firebase ID token is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Firebase Admin SDKを使ってトークンを検証し、ユーザー情報を取得
            firebase_user = self._verify_firebase_token(id_token)
            if not firebase_user:
                logger.warning("無効なFirebase IDトークンです")
                return Response(
                    {"error": "Invalid Firebase ID token"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # トランザクション内でユーザー処理を実行
            logger.info(f"Firebase認証成功: {firebase_user.get('email')}、ユーザー処理を開始します")
            with transaction.atomic():
                user, is_new_user = self._get_or_create_user(firebase_user)
                
                # JWTトークンを生成
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)
                
                logger.info(f"ユーザー {user.email} のJWTトークンを生成しました")
                
                # レスポンスを作成
                response_data = {
                    "message": "Firebase authentication successful",
                    "is_new_user": is_new_user,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "firebase_uid": firebase_user.get('uid'),
                        "firebase_name": firebase_user.get('name'),
                        "firebase_picture": firebase_user.get('picture')
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
                
                logger.info(f"ユーザー {user.email} の認証が完了しました。新規ユーザー: {is_new_user}")
                return response
                
        except transaction.TransactionManagementError as e:
            logger.error(f"トランザクションエラー: {e}", exc_info=True)
            return Response(
                {"error": "Database transaction error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            logger.error(f"Firebase認証エラー: {e}", exc_info=True)
            return Response(
                {"error": "Authentication failed"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _verify_firebase_token(self, id_token):
        """
        Firebase Admin SDKを使ってIDトークンを検証し、ユーザー情報を取得
        """
        try:
            logger.info("Firebase IDトークンの検証を開始します")
            # Firebase Admin SDKを使ってトークンを検証
            decoded_token = auth.verify_id_token(id_token)
            
            # ユーザー情報を取得
            uid = decoded_token.get('uid')
            if not uid:
                logger.warning("トークンにUIDが含まれていません")
                return None
            
            # Firebase Authからユーザー情報を取得
            firebase_user = auth.get_user(uid)
            
            # 必要な情報を辞書に格納
            user_info = {
                'uid': firebase_user.uid,
                'email': firebase_user.email,
                'name': firebase_user.display_name,
                'picture': firebase_user.photo_url,
                'provider_id': decoded_token.get('firebase', {}).get('sign_in_provider')
            }
            
            logger.info(f"Firebase IDトークンの検証に成功しました: {user_info.get('email')}")
            return user_info
            
        except auth.InvalidIdTokenError:
            logger.warning("無効なFirebase IDトークンです")
            return None
        except auth.ExpiredIdTokenError:
            logger.warning("期限切れのFirebase IDトークンです")
            return None
        except auth.RevokedIdTokenError:
            logger.warning("取り消されたFirebase IDトークンです")
            return None
        except auth.UserNotFoundError:
            logger.warning("ユーザーが見つかりません")
            return None
        except Exception as e:
            logger.error(f"Firebase IDトークン検証中に予期しないエラーが発生しました: {e}", exc_info=True)
            return None
    
    def _get_or_create_user(self, firebase_user):
        """
        Firebaseユーザー情報を基にユーザーを取得または作成
        """
        firebase_uid = firebase_user.get('uid')
        firebase_email = firebase_user.get('email')
        firebase_name = firebase_user.get('name', '')
        firebase_picture = firebase_user.get('picture', '')
        provider_id = firebase_user.get('provider_id', '')
        
        # Firebase認証情報でユーザーを検索
        try:
            firebase_auth = FirebaseAuthInfo.objects.get(firebase_uid=firebase_uid)
            user = firebase_auth.user
            is_new_user = False
            
            # 既存ユーザーのFirebase認証情報を更新
            firebase_auth.firebase_email = firebase_email
            firebase_auth.firebase_name = firebase_name
            firebase_auth.firebase_picture = firebase_picture
            firebase_auth.provider_id = provider_id
            firebase_auth.save()
            
            logger.info(f"既存のFirebase認証ユーザーでログインしました: {user.email}")
            
        except FirebaseAuthInfo.DoesNotExist:
            # 新規Firebase認証の場合
            
            # メールアドレスで既存ユーザーを検索
            try:
                user = CustomUser.objects.get(email=firebase_email)
                is_new_user = False
                logger.info(f"既存ユーザー({user.email})にFirebase認証情報を追加します")
                
                # 既存のユーザーにFirebase認証情報が既に関連付けられているか確認
                try:
                    existing_firebase_auth = FirebaseAuthInfo.objects.get(user=user)
                    # 既存のFirebase認証情報を更新
                    existing_firebase_auth.firebase_uid = firebase_uid
                    existing_firebase_auth.firebase_email = firebase_email
                    existing_firebase_auth.firebase_name = firebase_name
                    existing_firebase_auth.firebase_picture = firebase_picture
                    existing_firebase_auth.provider_id = provider_id
                    existing_firebase_auth.save()
                    logger.info(f"既存のFirebase認証情報を更新しました: {user.email}")
                except FirebaseAuthInfo.DoesNotExist:
                    # 新しいFirebase認証情報を作成
                    FirebaseAuthInfo.objects.create(
                        user=user,
                        firebase_uid=firebase_uid,
                        firebase_email=firebase_email,
                        firebase_name=firebase_name,
                        firebase_picture=firebase_picture,
                        provider_id=provider_id
                    )
                    logger.info(f"新しいFirebase認証情報を作成しました: {user.email}")
                
            except CustomUser.DoesNotExist:
                # 完全に新規のユーザーを作成
                is_new_user = True
                logger.info(f"新規ユーザーを作成します: {firebase_email}")
                
                user = CustomUser.objects.create_user(
                    email=firebase_email,
                    password=None  # Firebaseログインなのでパスワードは不要
                )
                
                # デフォルトプロフィールを作成
                UserProfile.objects.create(
                    user=user,
                    height=170.0,
                    weight=60.0,
                    nickname=firebase_name or firebase_email.split('@')[0],
                    name=firebase_name or firebase_email.split('@')[0]
                )
                
                # 新規ユーザー用のFirebase認証情報を作成
                FirebaseAuthInfo.objects.create(
                    user=user,
                    firebase_uid=firebase_uid,
                    firebase_email=firebase_email,
                    firebase_name=firebase_name,
                    firebase_picture=firebase_picture,
                    provider_id=provider_id
                )
                logger.info(f"新規ユーザーとFirebase認証情報を作成しました: {user.email}")
        
        # 最終ログイン時刻を更新
        user.last_login = timezone.now()
        user.save()
        
        return user, is_new_user

# Firebase認証状態確認ビュー
class FirebaseAuthStatusView(APIView):
    """
    現在のユーザーのFirebase認証状態を確認するビュー
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        user = request.user
        
        try:
            firebase_auth = FirebaseAuthInfo.objects.get(user=user)
            return Response({
                "is_firebase_authenticated": True,
                "firebase_email": firebase_auth.firebase_email,
                "firebase_name": firebase_auth.firebase_name,
                "firebase_picture": firebase_auth.firebase_picture,
                "provider_id": firebase_auth.provider_id
            }, status=status.HTTP_200_OK)
            
        except FirebaseAuthInfo.DoesNotExist:
            return Response({
                "is_firebase_authenticated": False
            }, status=status.HTTP_200_OK)
