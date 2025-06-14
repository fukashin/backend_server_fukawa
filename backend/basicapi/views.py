import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status,viewsets
from rest_framework_simplejwt.views import TokenRefreshView as BaseTokenRefreshView
from rest_framework_simplejwt.views import TokenObtainPairView as BaseTokenObtainPairView
from .models import UserProfile, WeightRecord, CalorieRecord, SleepRecord
from .serializers import RegisterSerializer, CustomTokenObtainPairSerializer, UserProfileSerializer, WeightRecordSerializer, CalorieRecordSerializer, SleepRecordSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.backends import TokenBackend
from django.conf import settings
import datetime as _dt     # ★ これを追加

# ログ設定
logger = logging.getLogger(__name__)

# ユーザー登録用ビュー
class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response(
                    {"message": "User registered successfully!"},
                    status=status.HTTP_201_CREATED
                )
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

        # 成功レスポンスを作成
        response = Response(
            {"message": "Logged in successfully."},
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
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer

# 体重履歴ビューセット
class WeightRecordViewSet(viewsets.ModelViewSet):
    queryset = WeightRecord.objects.all()
    serializer_class = WeightRecordSerializer

# カロリー記録ビューセット
class CalorieRecordViewSet(viewsets.ModelViewSet):
    queryset = CalorieRecord.objects.all()
    serializer_class = CalorieRecordSerializer

# 睡眠記録ビューセット
class SleepRecordViewSet(viewsets.ModelViewSet):
    queryset = SleepRecord.objects.all()
    serializer_class = SleepRecordSerializer


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