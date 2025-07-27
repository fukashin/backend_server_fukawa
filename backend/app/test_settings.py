from .settings import *

# テスト用にSQLiteデータベースを使用
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'test_db.sqlite3',
    }
}

# テスト用の設定
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Firebase Admin SDKの初期化をスキップ
FIREBASE_ADMIN_SKIP_INIT = True
