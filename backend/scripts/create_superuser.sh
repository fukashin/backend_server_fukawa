# superuser の情報
SUPERUSER_EMAIL=${DJANGO_SUPERUSER_EMAIL}
SUPERUSER_PASSWORD=${DJANGO_SUPERUSER_PASSWORD}

# superuser が存在しない場合のみ作成
echo "Checking for existing superuser..."
python manage.py shell -c "
import os
from django.contrib.auth import get_user_model

User = get_user_model()

superuser_email = os.environ.get('DJANGO_SUPERUSER_EMAIL', 'admin@example.com')
superuser_password = os.environ.get('DJANGO_SUPERUSER_PASSWORD', 'admin123')

if not superuser_email or not superuser_password:
    print('Error: Missing environment variables for superuser creation.')
else:
    if not User.objects.filter(email=superuser_email).exists():
        User.objects.create_superuser(email=superuser_email, password=superuser_password)
        print('Superuser created.')
    else:
        print('Superuser already exists.')
"
