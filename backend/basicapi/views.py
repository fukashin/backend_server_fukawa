from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import CustomUser
from .serializers import FirebaseRegisterSerializer, UserSerializer
import firebase_admin
from firebase_admin import auth, credentials
from django.db import transaction
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate

# Firebase初期化（既に初期化済ならスキップ）
try:
    firebase_admin.get_app()
except ValueError:
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)

class FirebaseRegisterView(APIView):
    """
    Firebaseトークンで登録のみを行うエンドポイント
    """

    def post(self, request):
        id_token = request.data.get('id_token')

        if not id_token:
            return Response({"error": "id_token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            decoded_token = auth.verify_id_token(id_token)
            uid = decoded_token['uid']
            email = decoded_token.get('email')

            if not email:
                return Response({"error": "Email is required in Firebase token"}, status=status.HTTP_400_BAD_REQUEST)

            with transaction.atomic():
                user, created = CustomUser.objects.get_or_create(
                    firebase_uid=uid,
                    defaults={'email': email, 'username': email}
                )

            serializer = FirebaseRegisterSerializer(user)
            return Response({
                "user": serializer.data,
                "created": created
            }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)


class FirebaseAuthView(APIView):
    """
    Firebase認証後にJWTトークンを生成するエンドポイント
    """

    def post(self, request):
        id_token = request.data.get('id_token')

        if not id_token:
            return Response({"error": "id_token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Firebaseトークンを検証
            decoded_token = auth.verify_id_token(id_token)
            uid = decoded_token['uid']
            email = decoded_token.get('email')

            if not email:
                return Response({"error": "Email is required in Firebase token"}, status=status.HTTP_400_BAD_REQUEST)

            # ユーザーを取得または作成
            with transaction.atomic():
                user, created = CustomUser.objects.get_or_create(
                    firebase_uid=uid,
                    defaults={'email': email, 'username': email}
                )

            # JWTトークンを生成
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token

            # レスポンスを作成
            response_data = {
                'access_token': str(access_token),
                'refresh_token': str(refresh),
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'firebase_uid': user.firebase_uid
                },
                'created': created
            }

            response = Response(response_data, status=status.HTTP_200_OK)
            
            # Cookieにトークンを設定（オプション）
            response.set_cookie(
                'access_token',
                str(access_token),
                max_age=60 * 60 * 10,  # 10時間
                httponly=True,
                secure=False,  # 開発環境ではFalse、本番環境ではTrue
                samesite='Lax'
            )
            
            response.set_cookie(
                'refresh_token',
                str(refresh),
                max_age=60 * 60 * 24 * 7,  # 7日間
                httponly=True,
                secure=False,  # 開発環境ではFalse、本番環境ではTrue
                samesite='Lax'
            )

            return response

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)


class EmailPasswordAuthView(APIView):
    """
    メールアドレスとパスワードによる認証エンドポイント
    """

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response(
                {"error": "Email and password are required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Firebaseでメール・パスワード認証を行う
            # 注意: この部分はFirebase Admin SDKではクライアント側の認証を直接行えないため、
            # 実際の実装ではクライアント側でFirebase認証を行い、そのトークンをこのエンドポイントに送信する
            
            # 既存ユーザーをメールアドレスで検索
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return Response(
                    {"error": "User not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )

            # JWTトークンを生成
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token

            response_data = {
                'access_token': str(access_token),
                'refresh_token': str(refresh),
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'firebase_uid': user.firebase_uid
                }
            }

            response = Response(response_data, status=status.HTTP_200_OK)
            
            # Cookieにトークンを設定
            response.set_cookie(
                'access_token',
                str(access_token),
                max_age=60 * 60 * 10,  # 10時間
                httponly=True,
                secure=False,
                samesite='Lax'
            )
            
            response.set_cookie(
                'refresh_token',
                str(refresh),
                max_age=60 * 60 * 24 * 7,  # 7日間
                httponly=True,
                secure=False,
                samesite='Lax'
            )

            return response

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    """
    ログアウトエンドポイント
    """

    def post(self, request):
        response = Response({"message": "Successfully logged out"}, status=status.HTTP_200_OK)
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response
