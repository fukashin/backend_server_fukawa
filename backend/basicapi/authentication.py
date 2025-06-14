from rest_framework_simplejwt.authentication import JWTAuthentication

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Cookieからaccess tokenを取得
        token = request.COOKIES.get('access_token')
        if token is None:
            return None

        try:
            validated_token = self.get_validated_token(token)
        except Exception:
            return None

        user = self.get_user(validated_token)
        return (user, validated_token)