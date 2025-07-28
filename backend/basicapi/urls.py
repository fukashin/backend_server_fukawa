from django.urls import path, include
from .views import RegisterView, CustomTokenObtainPairView, UserProfileViewSet, WeightRecordViewSet, CalorieRecordViewSet, SleepRecordViewSet, AuthStatusView, CookieUserInfoView, StandardUserInfoView, LogoutView, DailyRecordUpsertAPIView, FirebaseAuthView, FirebaseAuthStatusView, UserRegistrationView, UserInfoView, FirebaseTokenVerifyView, HealthCheckView
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

router = DefaultRouter()
router.register(r'user-profiles', UserProfileViewSet, basename='userprofile')
router.register(r'weight-records', WeightRecordViewSet, basename='weightrecord')
router.register(r'calorie-records', CalorieRecordViewSet, basename='calorierecord')
router.register(r'sleep-records', SleepRecordViewSet, basename='sleeprecord')

urlpatterns = [
    # ユーザー登録
    path('register/', RegisterView.as_view(), name='register'),
    # JWT トークン取得
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'), # CustomTokenObtainPairView.as_view(),
    # JWT トークンリフレッシュ
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # 認証
    path('auth/status/', AuthStatusView.as_view(), name='auth_status'),
    path('userinfo/', CookieUserInfoView.as_view(), name='user_info'),
    path('userinfo-standard/', StandardUserInfoView.as_view(), name='user_info_standard'),
    # Firebase認証
    path('auth/firebase/', FirebaseAuthView.as_view(), name='firebase_auth'),
    path('auth/firebase/status/', FirebaseAuthStatusView.as_view(), name='firebase_auth_status'),
    # 新しいFlutterアプリ用のAPIエンドポイント
    path('users/register/', UserRegistrationView.as_view(), name='user_registration'),
    path('users/<str:firebase_uid>/', UserInfoView.as_view(), name='user_info_by_uid'),
    path('auth/verify-token/', FirebaseTokenVerifyView.as_view(), name='firebase_token_verify'),
    path('auth/google/register/', UserRegistrationView.as_view(), name='google_auth_register'),
    path('auth/apple/register/', UserRegistrationView.as_view(), name='apple_auth_register'),
    path('health/', HealthCheckView.as_view(), name='health_check'),
    # ログアウト
    path('logout/', LogoutView.as_view(), name='logout'),
    path('', include(router.urls)),
    path("daily-records/", DailyRecordUpsertAPIView.as_view(), name="daily-records"),

]
